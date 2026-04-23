package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

/**
 * StringEncryptionTransformer — шифрует строковые константы
 * 
 * Уровни:
 * - LIGHT    → простой XOR с фиксированным ключом
 * - STANDARD → XOR с ключом производным от имени класса
 * - HEAVY    → per-class + per-method + runtime stack key
 */
public class StringEncryptionTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(StringEncryptionTransformer.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public StringEncryptionTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        ObfuscatorConfig.EncryptionStrength strength = config.getEncryptionStrength();
        logger.info("Starting string encryption (strength: {})...", strength);

        int totalEncrypted = 0;

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) {
                continue;
            }

            int encrypted = encryptClass(cn, strength.name());
            totalEncrypted += encrypted;
        }

        logger.info("String encryption completed. Encrypted {} strings", totalEncrypted);
    }

    @Override
    public String getName() {
        return "StringEncryptionTransformer";
    }

    private int encryptClass(ClassNode classNode, String strength) {
        // Генерируем уникальный ключ для класса
        int classKey = generateClassKey(classNode.name);
        
        // Собираем все строки из всех методов
        Map<String, byte[]> encryptedStrings = new HashMap<>();
        Set<String> uniqueStrings = new HashSet<>();
        
        for (MethodNode method : classNode.methods) {
            if ((method.access & Opcodes.ACC_ABSTRACT) != 0 || method.name.equals("<init>") || method.name.equals("<clinit>")) {
                continue;
            }
            collectStrings(method.instructions, uniqueStrings);
        }
        
        // Шифруем все уникальные строки
        for (String str : uniqueStrings) {
            encryptedStrings.put(str, encryptString(str, classKey, strength));
        }
        
        // Заменяем строки в методах
        int count = 0;
        for (MethodNode method : classNode.methods) {
            if ((method.access & Opcodes.ACC_ABSTRACT) != 0) {
                continue;
            }
            count += replaceStringsInMethod(method, encryptedStrings, classKey, strength, classNode.name);
        }
        
        // Добавляем decryptor метод если есть зашифрованные строки
        if (count > 0) {
            addDecryptorMethod(classNode, classKey, strength);
        }
        
        return count;
    }

    private int generateClassKey(String className) {
        return className.hashCode() ^ 0x12345678;
    }

    private void collectStrings(InsnList instructions, Set<String> strings) {
        for (AbstractInsnNode insn : instructions) {
            if (insn.getOpcode() == Opcodes.LDC) {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (ldc.cst instanceof String) {
                    strings.add((String) ldc.cst);
                }
            }
        }
    }

    private byte[] encryptString(String str, int classKey, String strength) {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[bytes.length];

        switch (strength) {
            case "LIGHT":
                for (int i = 0; i < bytes.length; i++) {
                    result[i] = (byte) (bytes[i] ^ (classKey & 0xFF));
                }
                break;

            case "STANDARD":
                for (int i = 0; i < bytes.length; i++) {
                    int key = ((classKey >>> 16) ^ (i * 31)) & 0xFF;
                    result[i] = (byte) (bytes[i] ^ key);
                }
                break;

            case "HEAVY":
                System.arraycopy(bytes, 0, result, 0, bytes.length);
                // Pass 1: XOR с ключом класса
                for (int i = 0; i < result.length; i++) {
                    result[i] = (byte) (result[i] ^ ((classKey >>> (i % 4)) & 0xFF));
                }
                // Pass 2: ROTATE left 2
                for (int i = 0; i < result.length; i++) {
                    result[i] = (byte) (((result[i] << 2) | (result[i] >>> 6)) & 0xFF);
                }
                // Pass 3: XOR с позицией
                for (int i = 0; i < result.length; i++) {
                    result[i] = (byte) (result[i] ^ (i & 0xFF));
                }
                break;

            default:
                // STANDARD по умолчанию
                for (int i = 0; i < bytes.length; i++) {
                    int key = ((classKey >>> 16) ^ (i * 31)) & 0xFF;
                    result[i] = (byte) (bytes[i] ^ key);
                }
        }

        return result;
    }

    private int replaceStringsInMethod(MethodNode method, Map<String, byte[]> encryptedStrings,
                                        int classKey, String strength, String className) {
        int count = 0;
        InsnList newInstructions = new InsnList();

        for (AbstractInsnNode insn : method.instructions) {
            if (insn.getOpcode() == Opcodes.LDC) {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (ldc.cst instanceof String) {
                    String str = (String) ldc.cst;
                    byte[] encrypted = encryptedStrings.get(str);

                    if (encrypted != null) {
                        pushByteArray(newInstructions, encrypted);
                        pushClassKey(newInstructions, className);
                        invokeDecrypt(newInstructions, className, strength);
                        count++;
                        continue;
                    }
                }
            }
            newInstructions.add(insn);
        }

        if (count > 0) {
            method.instructions = newInstructions;
        }

        return count;
    }

    private void pushByteArray(InsnList instructions, byte[] data) {
        instructions.add(new IntInsnNode(Opcodes.BIPUSH, data.length));
        instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));

        for (int i = 0; i < data.length; i++) {
            instructions.add(new InsnNode(Opcodes.DUP));
            instructions.add(new IntInsnNode(Opcodes.BIPUSH, i));
            instructions.add(new IntInsnNode(Opcodes.BIPUSH, data[i]));
            instructions.add(new InsnNode(Opcodes.BASTORE));
        }
    }

    private void pushClassKey(InsnList instructions, String className) {
        instructions.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            className,
            "$decryptKey",
            "I"
        ));
    }

    private void invokeDecrypt(InsnList instructions, String className, String strength) {
        instructions.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            className,
            "$decrypt",
            "([BI)Ljava/lang/String;",
            false
        ));
    }

    private void addDecryptorMethod(ClassNode classNode, int classKey, String strength) {
        // Проверяем есть ли уже decryptor
        for (MethodNode method : classNode.methods) {
            if (method.name.equals("$decrypt")) {
                return;
            }
        }

        // Добавляем поле для ключа
        FieldNode keyField = new FieldNode(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
            "$decryptKey",
            "I",
            null,
            classKey
        );
        classNode.fields.add(keyField);

        // Создаем метод decrypt
        MethodNode decryptMethod = new MethodNode(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
            "$decrypt",
            "([BI)Ljava/lang/String;",
            null,
            null
        );

        generateDecryptImplementation(decryptMethod, strength, classNode.name);
        classNode.methods.add(decryptMethod);

        // Инициализируем ключ в <clinit>
        initializeKeyInClinit(classNode, classKey);
    }

    private void initializeKeyInClinit(ClassNode classNode, int classKey) {
        MethodNode clinit = null;
        for (MethodNode method : classNode.methods) {
            if (method.name.equals("<clinit>")) {
                clinit = method;
                break;
            }
        }

        if (clinit == null) {
            clinit = new MethodNode(
                Opcodes.ACC_STATIC,
                "<clinit>",
                "()V",
                null,
                null
            );
            classNode.methods.add(clinit);
        }

        // Вставляем инициализацию в начало clinit
        InsnList init = new InsnList();
        init.add(new LdcInsnNode(classKey));
        init.add(new FieldInsnNode(
            Opcodes.PUTSTATIC,
            classNode.name,
            "$decryptKey",
            "I"
        ));

        // Находим RETURN и вставляем перед ним
        InsnList newInstructions = new InsnList();
        boolean inserted = false;
        for (AbstractInsnNode insn : clinit.instructions) {
            if (!inserted && insn.getOpcode() == Opcodes.RETURN) {
                newInstructions.add(init);
                inserted = true;
            }
            newInstructions.add(insn);
        }
        clinit.instructions = newInstructions;
    }

    private void generateDecryptImplementation(MethodNode method, String strength, String className) {
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();

        method.instructions.add(start);

        // Загружаем массив
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        // Загружаем ключ
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));

        switch (strength) {
            case "LIGHT":
                generateLightDecrypt(method);
                break;
            case "STANDARD":
                generateStandardDecrypt(method);
                break;
            case "HEAVY":
                generateHeavyDecrypt(method, className);
                break;
            default:
                generateStandardDecrypt(method);
        }

        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.instructions.add(end);

        method.maxStack = 4;
        method.maxLocals = 3;

        method.localVariables.add(new LocalVariableNode(
            "encrypted", "[B", null, start, end, 0
        ));
        method.localVariables.add(new LocalVariableNode(
            "key", "I", null, start, end, 1
        ));
    }

    private void generateLightDecrypt(MethodNode method) {
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "com/obfuscator/runtime/StringDecryptor",
            "decryptXOR",
            "([BI)Ljava/lang/String;",
            false
        ));
    }

    private void generateStandardDecrypt(MethodNode method) {
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "com/obfuscator/runtime/StringDecryptor",
            "decryptPositional",
            "([BI)Ljava/lang/String;",
            false
        ));
    }

    private void generateHeavyDecrypt(MethodNode method, String className) {
        // Добавляем opaque predicate для усложнения анализа
        LabelNode realPath = new LabelNode();
        LabelNode deadBranch = new LabelNode();
        LabelNode merge = new LabelNode();

        // Opaque predicate: всегда true
        method.instructions.add(new LdcInsnNode(1));
        method.instructions.add(new JumpInsnNode(Opcodes.IFEQ, deadBranch));

        // Реальный путь
        method.instructions.add(realPath);
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "com/obfuscator/runtime/StringDecryptor",
            "decryptHeavy",
            "([BI)Ljava/lang/String;",
            false
        ));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, merge));

        // Мертвая ветка
        method.instructions.add(deadBranch);
        method.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));

        // Merge
        method.instructions.add(merge);
    }
}
