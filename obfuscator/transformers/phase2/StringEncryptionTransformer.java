package transformers.phase2;

import core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Encrypts string literals with various strength levels.
 */
public class StringEncryptionTransformer {
    private static final Logger LOG = LoggerFactory.getLogger(StringEncryptionTransformer.class);

    public enum Strength {
        LIGHT,      // Simple XOR with static key
        STANDARD,   // Per-class key
        HEAVY,      // Per-string unique key based on context
        SUPER_HEAVY // Runtime stack-based decryption
    }

    private final ClassPool pool;
    private final Strength strength;
    private final boolean inlineDecryptor;
    private final boolean useSwitchDispatch;
    private final Random random = new Random(42);

    public StringEncryptionTransformer(ClassPool pool, Strength strength, 
                                       boolean inlineDecryptor, boolean useSwitchDispatch) {
        this.pool = pool;
        this.strength = strength;
        this.inlineDecryptor = inlineDecryptor;
        this.useSwitchDispatch = useSwitchDispatch;
    }

    public void transform() {
        LOG.info("Starting string encryption (strength={}, inline={}, switch={})...", 
                strength, inlineDecryptor, useSwitchDispatch);
        int totalEncrypted = 0;

        for (ClassNode cn : pool.getOwnClasses()) {
            int classEncrypted = encryptClass(cn);
            if (classEncrypted > 0 && inlineDecryptor) {
                injectDecryptor(cn);
            }
            totalEncrypted += classEncrypted;
        }

        LOG.info("String encryption complete: {} strings encrypted", totalEncrypted);
    }

    private int encryptClass(ClassNode cn) {
        int count = 0;

        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            count += encryptMethod(cn, mn);
        }

        return count;
    }

    private int encryptMethod(ClassNode cn, MethodNode mn) {
        int count = 0;
        List<LdcInsnNode> stringsToEncrypt = new ArrayList<>();

        // Find all string loads
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String str) {
                // Skip empty strings and very short strings
                if (str.length() <= 1) continue;
                stringsToEncrypt.add(ldc);
            }
        }

        // Encrypt each string
        for (LdcInsnNode ldc : stringsToEncrypt) {
            encryptInstruction(cn, mn, ldc);
            count++;
        }

        return count;
    }

    private void encryptInstruction(ClassNode cn, MethodNode mn, LdcInsnNode ldc) {
        String original = (String) ldc.cst;
        InsnList replacement = new InsnList();

        byte[] encrypted;
        int key;

        switch (strength) {
            case LIGHT -> {
                // Simple XOR with fixed key
                key = 0xDEADBEEF;
                encrypted = xorEncode(original.getBytes(StandardCharsets.UTF_8), key);
            }

            case STANDARD -> {
                // Per-class key
                key = cn.name.hashCode() ^ 0xDEADBEEF;
                encrypted = xorEncode(original.getBytes(StandardCharsets.UTF_8), key);
            }

            case HEAVY -> {
                // Per-string unique key based on class + method + position
                key = (cn.name.hashCode() * 31 + mn.name.hashCode()) ^ 
                      System.identityHashCode(ldc);
                encrypted = xorEncode(original.getBytes(StandardCharsets.UTF_8), key);
            }

            case SUPER_HEAVY -> {
                // Key derived from runtime state
                key = original.hashCode() ^ random.nextInt();
                encrypted = xorEncode(original.getBytes(StandardCharsets.UTF_8), key);
            }

            default -> throw new IllegalStateException("Unknown strength: " + strength);
        }

        // Build bytecode to decrypt at runtime
        if (useSwitchDispatch) {
            buildSwitchDispatch(replacement, encrypted, key, cn, mn);
        } else {
            buildDirectDecrypt(replacement, encrypted, key);
        }

        // Replace the LDC instruction
        mn.instructions.insert(ldc, replacement);
        mn.instructions.remove(ldc);
    }

    private void buildDirectDecrypt(InsnList out, byte[] encrypted, int key) {
        // Push encrypted bytes as array
        pushByteArray(out, encrypted);
        
        // Push key
        out.add(new IntInsnNode(Opcodes.SIPUSH, key & 0x7FFF));
        
        // Call decryptor
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            getDecryptorClass(), "decrypt", "([BI)Ljava/lang/String;", false));
    }

    private void buildSwitchDispatch(InsnList out, byte[] encrypted, int key, 
                                      ClassNode cn, MethodNode mn) {
        // Create opaque dispatch value
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            "java/lang/System", "currentTimeMillis", "()J", false));
        out.add(new IntInsnNode(Opcodes.SIPUSH, 1000));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            "java/lang/Math", "floorMod", "(JI)I", false));
        
        // Store dispatch value
        LabelNode[] cases = new LabelNode[3];
        for (int i = 0; i < 3; i++) {
            cases[i] = new LabelNode();
        }
        LabelNode endLabel = new LabelNode();

        // Create switch table
        int[] keys = new int[3];
        for (int i = 0; i < 3; i++) {
            keys[i] = random.nextInt(1000);
        }
        
        // This is simplified - full implementation would create proper switch
        pushByteArray(out, encrypted);
        out.add(new IntInsnNode(Opcodes.SIPUSH, key & 0x7FFF));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            getDecryptorClass(), "decrypt", "([BI)Ljava/lang/String;", false));
    }

    private void pushByteArray(InsnList out, byte[] data) {
        if (data.length == 0) {
            out.add(new IntInsnNode(Opcodes.BIPUSH, 0));
            out.add(new IntInsnNode(Opcodes.NEWARRAY, org.objectweb.asm.Opcodes.T_BYTE));
            return;
        }

        out.add(new IntInsnNode(Opcodes.BIPUSH, data.length));
        out.add(new IntInsnNode(Opcodes.NEWARRAY, org.objectweb.asm.Opcodes.T_BYTE));

        for (int i = 0; i < data.length; i++) {
            out.add(new InsnNode(Opcodes.DUP));
            out.add(new IntInsnNode(Opcodes.BIPUSH, i));
            out.add(new IntInsnNode(Opcodes.BIPUSH, data[i]));
            out.add(new InsnNode(Opcodes.BASTORE));
        }
    }

    private byte[] xorEncode(byte[] data, int key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ ((key >> ((i % 4) * 8)) & 0xFF));
        }
        return result;
    }

    private String getDecryptorClass() {
        // Will be injected into the JAR
        return "com/obf/runtime/StringDecryptor";
    }

    private void injectDecryptor(ClassNode cn) {
        // Add decryptor method directly to the class
        MethodNode decryptor = new MethodNode(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
            generateDecryptorName(),
            "([BI)Ljava/lang/String;",
            null,
            null
        );

        // Generate decryptor bytecode
        generateDecryptorBody(decryptor);

        cn.methods.add(decryptor);
    }

    private String generateDecryptorName() {
        String[] names = {"a", "b", "c", "\u0000", "\u0001"};
        return names[random.nextInt(names.length)];
    }

    private void generateDecryptorBody(MethodNode mn) {
        // Local variable indices
        // 0: byte[] encrypted
        // 1: int key
        // 2: byte[] result (local var)
        // 3: int i (loop counter)

        InsnList insns = mn.instructions;

        // Allocate result array
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, org.objectweb.asm.Opcodes.T_BYTE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // Loop setup
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 3));

        LabelNode loopStart = new LabelNode();
        LabelNode loopEnd = new LabelNode();

        insns.add(loopStart);

        // Loop condition: i < encrypted.length
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // result[i] = (byte)(encrypted[i] ^ (key >> ((i % 4) * 8)))
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));

        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new InsnNode(Opcodes.BALOAD));

        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new IntInsnNode(Opcodes.BIPUSH, 4));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            "java/lang/Math", "floorMod", "(II)I", false));
        insns.add(new IntInsnNode(Opcodes.BIPUSH, 3));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            "java/lang/Math", "multiplyExact", "(II)I", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            "java/lang/Integer", "rotateRight", "(II)I", false));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new IntInsnNode(Opcodes.BIPUSH, 0xFF));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new IntInsnNode(Opcodes.BIPUSH, 0));
        insns.add(new InsnNode(Opcodes.I2B));

        insns.add(new InsnNode(Opcodes.BASTORE));

        // i++
        insns.add(new IincInsnNode(3, 1));

        // Jump back to loop start
        insns.add(new JumpInsnNode(Opcodes.GOTO, loopStart));

        insns.add(loopEnd);

        // Convert byte[] to String
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC,
            "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
        insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
            "java/lang/String", "<init>", "([BLjava/nio/charset/Charset;)V", false));
        insns.add(new InsnNode(Opcodes.ARETURN));

        mn.maxStack = 6;
        mn.maxLocals = 4;
    }
}
