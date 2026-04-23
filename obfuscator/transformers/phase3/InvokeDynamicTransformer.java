package obfuscator.transformers.phase3;

import obfuscator.core.ClassPool;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * InvokeDynamicTransformer - заменяет обычные вызовы методов на invokedynamic.
 * 
 * Это самый мощный трансформер - декомпиляторы не знают что делает кастомный bootstrap.
 */
public class InvokeDynamicTransformer implements Opcodes {
    private static final Logger LOG = LoggerFactory.getLogger(InvokeDynamicTransformer.class);
    
    private final ClassPool pool;
    private final boolean encryptBootstrapArgs;
    private final Random random = new Random(42);
    
    // Bootstrap метод который будет вшит в каждый класс
    private static final String BOOTSTRAP_NAME = "λbootstrap";
    private static final String BOOTSTRAP_DESC = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/invoke/CallSite;";
    
    public InvokeDynamicTransformer(ClassPool pool, boolean encryptBootstrapArgs) {
        this.pool = pool;
        this.encryptBootstrapArgs = encryptBootstrapArgs;
    }
    
    public void transform() {
        LOG.info("Starting invokedynamic transformation (encrypt={}, auto-detect-lambdas=true)", encryptBootstrapArgs);
        
        int transformedCalls = 0;
        
        for (ClassNode cn : pool.getOwnClassesCollection()) {
            // Пропускаем интерфейсы
            if ((cn.access & ACC_INTERFACE) != 0) continue;
            
            // Пропускаем классы с лямбдами (уже используют invokedynamic)
            if (hasLambdas(cn)) {
                LOG.debug("Skipping class {} with existing lambdas", cn.name);
                continue;
            }
            
            // Добавляем bootstrap метод в класс
            addBootstrapMethod(cn);
            
            for (MethodNode mn : cn.methods) {
                // Пропускаем конструкторы, статические инициализаторы, мосты
                if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name) ||
                    (mn.access & ACC_BRIDGE) != 0 || (mn.access & ACC_NATIVE) != 0) {
                    continue;
                }
                
                try {
                    transformedCalls += transformMethod(cn, mn);
                } catch (Exception e) {
                    LOG.debug("Failed to transform method {}.{}{}: {}", 
                             cn.name, mn.name, mn.desc, e.getMessage());
                }
            }
        }
        
        LOG.info("Invokedynamic transformation complete: {} calls transformed", transformedCalls);
    }
    
    /**
     * Проверяет есть ли в классе уже лямбды (invokedynamic с LambdaMetafactory)
     */
    public static boolean hasLambdas(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof InvokeDynamicInsnNode idyn) {
                    if (idyn.bsm != null && 
                        idyn.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    /**
     * Добавляет bootstrap метод в класс
     */
    private void addBootstrapMethod(ClassNode cn) {
        // Проверяем есть ли уже bootstrap метод
        for (MethodNode mn : cn.methods) {
            if (BOOTSTRAP_NAME.equals(mn.name) && BOOTSTRAP_DESC.equals(mn.desc)) {
                return; // Уже есть
            }
        }
        
        // Создаём bootstrap метод
        MethodNode bootstrap = new MethodNode(
            ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC,
            BOOTSTRAP_NAME,
            BOOTSTRAP_DESC,
            null,
            null
        );
        
        // Генерируем байткод bootstrap метода
        // Bootstrap принимает зашифрованные имена класса и метода,
        // расшифровывает и возвращает CallSite
        
        InsnList code = new InsnList();
        
        // Локальные переменные:
        // 0: lookup (MethodHandles$Lookup)
        // 1: name (String) - имя вызываемого метода (зашифровано)
        // 2: type (MethodType)
        // 3: className (String) - зашифрованное имя класса
        // 4: methodName (String) - зашифрованное имя метода
        
        int localKey = 5;
        int localDecryptedClass = 6;
        int localDecryptedMethod = 7;
        int localMethodHandle = 8;
        
        // XOR ключ для расшифровки (простой XOR для скорости)
        int xorKey = 0x5A ^ cn.name.hashCode();
        code.add(new LdcInsnNode(xorKey));
        code.add(new VarInsnNode(ISTORE, localKey));
        
        // Расшифровываем имя класса
        code.add(new VarInsnNode(ALOAD, 3)); // зашифрованное имя класса
        code.add(new VarInsnNode(ILOAD, localKey));
        code.add(new MethodInsnNode(INVOKESTATIC, "obfuscator/runtime/StringDecryptor", 
                                    "decrypt", "(Ljava/lang/String;I)Ljava/lang/String;", false));
        code.add(new VarInsnNode(ASTORE, localDecryptedClass));
        
        // Расшифровываем имя метода
        code.add(new VarInsnNode(ALOAD, 4)); // зашифрованное имя метода
        code.add(new VarInsnNode(ILOAD, localKey));
        code.add(new MethodInsnNode(INVOKESTATIC, "obfuscator/runtime/StringDecryptor", 
                                    "decrypt", "(Ljava/lang/String;I)Ljava/lang/String;", false));
        code.add(new VarInsnNode(ASTORE, localDecryptedMethod));
        
        // Загружаем класс через Class.forName
        code.add(new VarInsnNode(ALOAD, localDecryptedClass));
        code.add(new InsnNode(ICONST_1)); // initialize = true
        code.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Class", 
                                    "forName", "(Ljava/lang/String;Z)Ljava/lang/Class;", false));
        
        // Находим метод
        code.add(new VarInsnNode(ALOAD, localDecryptedMethod));
        code.add(new VarInsnNode(ALOAD, 2)); // MethodType
        code.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", 
                                    "getMethodDescriptor", "(Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/reflect/Method;", false));
        
        // Получаем MethodHandle
        code.add(new VarInsnNode(ALOAD, 0)); // lookup
        code.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", 
                                    "unreflect", "(Ljava/lang/reflect/Method;)Ljava/lang/invoke/MethodHandle;", false));
        code.add(new VarInsnNode(ASTORE, localMethodHandle));
        
        // Создаём ConstantCallSite
        code.add(new TypeInsnNode(NEW, "java/lang/invoke/ConstantCallSite"));
        code.add(new InsnNode(DUP));
        code.add(new VarInsnNode(ALOAD, localMethodHandle));
        code.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/invoke/ConstantCallSite", 
                                    "<init>", "(Ljava/lang/invoke/MethodHandle;)V", false));
        code.add(new InsnNode(ARETURN));
        
        bootstrap.instructions = code;
        bootstrap.maxLocals = localMethodHandle + 1;
        bootstrap.maxStack = 4;
        
        cn.methods.add(bootstrap);
    }
    
    /**
     * Трансформирует вызовы методов в методе
     */
    private int transformMethod(ClassNode cn, MethodNode mn) {
        int transformed = 0;
        List<AbstractInsnNode> toTransform = new ArrayList<>();
        
        // Находим кандидаты для трансформации
        for (AbstractInsnNode insn : mn.instructions) {
            if (!(insn instanceof MethodInsnNode methodInsn)) continue;
            
            // Пропускаем INVOKESPECIAL (конструкторы, super вызовы)
            if (methodInsn.getOpcode() == INVOKESPECIAL) continue;
            
            // Пропускаем вызовы в JDK которые могут быть критичны
            if (methodInsn.owner.startsWith("java/lang/invoke/")) continue;
            
            // Пропускаем методы с аннотациями (если бы они были видны здесь)
            
            toTransform.add(insn);
        }
        
        // Трансформируем найденные вызовы
        for (AbstractInsnNode insn : toTransform) {
            MethodInsnNode methodInsn = (MethodInsnNode) insn;
            
            try {
                replaceWithInvokeDynamic(cn, mn, methodInsn);
                transformed++;
            } catch (Exception e) {
                LOG.debug("Failed to transform call to {}.{}{}", 
                         methodInsn.owner, methodInsn.name, methodInsn.desc);
            }
        }
        
        return transformed;
    }
    
    /**
     * Заменяет INVOKEVIRTUAL/INVOKESTATIC на INVOKEDYNAMIC
     */
    private void replaceWithInvokeDynamic(ClassNode cn, MethodNode mn, MethodInsnNode original) {
        // Шифруем имена класса и метода
        int xorKey = 0x5A ^ cn.name.hashCode();
        String encryptedClass = encrypt(original.owner, xorKey);
        String encryptedMethod = encrypt(original.name, xorKey);
        
        // Создаём Handle для bootstrap метода
        Handle bootstrapHandle = new Handle(
            H_INVOKESTATIC,
            cn.name,
            BOOTSTRAP_NAME,
            BOOTSTRAP_DESC,
            false
        );
        
        // Создаём InvokeDynamicInsnNode
        InvokeDynamicInsnNode idyn = new InvokeDynamicInsnNode(
            original.name, // Имя (может быть любым, используется для отладки)
            original.desc, // Дескриптор метода
            bootstrapHandle,
            encryptedClass,
            encryptedMethod
        );
        
        // Заменяем инструкцию
        mn.instructions.insert(original, idyn);
        mn.instructions.remove(original);
    }
    
    /**
     * Простое XOR шифрование строки
     */
    private String encrypt(String str, int key) {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] ^= (byte)((key >> (i % 4) * 8) & 0xFF);
        }
        // Кодируем в base64-like формат для безопасного хранения в bytecode
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}
