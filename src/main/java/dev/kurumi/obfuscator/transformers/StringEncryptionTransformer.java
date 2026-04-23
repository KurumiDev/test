package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Replaces {@code LDC} string constants with calls to a synthesized per-class
 * decrypt method. Keys are derived from the class name and, in HEAVY mode,
 * from the enclosing method too.
 */
public class StringEncryptionTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(StringEncryptionTransformer.class);

    private static final String DECRYPT_NAME_STANDARD = "$obfD";
    private static final String DECRYPT_NAME_HEAVY = "$obfDH";
    private static final String DECRYPT_DESC_STANDARD = "(Ljava/lang/String;)Ljava/lang/String;";
    private static final String DECRYPT_DESC_HEAVY = "(Ljava/lang/String;I)Ljava/lang/String;";

    @Override
    public String name() {
        return "string-encryption";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        ObfuscatorConfig.StringStrength strength = ctx.config().stringStrength();
        int classesTouched = 0;
        int stringsEncrypted = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) continue;
            if (cn.name.endsWith("/package-info")) continue;

            int classKey = deriveClassKey(cn.name);
            boolean classTouched = false;

            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals(DECRYPT_NAME_STANDARD) || mn.name.equals(DECRYPT_NAME_HEAVY)) continue;

                InsnList insns = mn.instructions;
                List<AbstractInsnNode> ldcNodes = new java.util.ArrayList<>();
                for (AbstractInsnNode insn : insns.toArray()) {
                    if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                        if (s.isEmpty()) continue;
                        ldcNodes.add(ldc);
                    }
                }
                if (ldcNodes.isEmpty()) continue;

                int methodKey = strength == ObfuscatorConfig.StringStrength.HEAVY
                        ? deriveMethodKey(mn.name, mn.desc) : 0;

                for (AbstractInsnNode insn : ldcNodes) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    String original = (String) ldc.cst;
                    String encoded = encode(original, classKey + methodKey);
                    ldc.cst = encoded;
                    InsnList replacement = new InsnList();
                    if (strength == ObfuscatorConfig.StringStrength.HEAVY) {
                        replacement.add(pushInt(methodKey));
                        replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name,
                                DECRYPT_NAME_HEAVY, DECRYPT_DESC_HEAVY, (cn.access & Opcodes.ACC_INTERFACE) != 0));
                    } else {
                        replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name,
                                DECRYPT_NAME_STANDARD, DECRYPT_DESC_STANDARD, (cn.access & Opcodes.ACC_INTERFACE) != 0));
                    }
                    insns.insert(ldc, replacement);
                    classTouched = true;
                    stringsEncrypted++;
                }
            }

            if (classTouched) {
                injectDecryptMethod(cn, classKey, strength);
                classesTouched++;
            }
        }
        log.info("Encrypted {} strings across {} classes", stringsEncrypted, classesTouched);
    }

    private int deriveClassKey(String internalName) {
        int h = 0x9E3779B1;
        for (int i = 0; i < internalName.length(); i++) {
            h = Integer.rotateLeft(h ^ internalName.charAt(i), 5) * 0x85EBCA77;
        }
        return h | 1;
    }

    private int deriveMethodKey(String name, String desc) {
        int h = 0x27D4EB2F;
        String s = name + desc;
        for (int i = 0; i < s.length(); i++) {
            h = Integer.rotateLeft(h ^ s.charAt(i), 7) * 0xC2B2AE35;
        }
        return h;
    }

    private String encode(String original, int key) {
        byte[] in = original.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[in.length];
        int k = key;
        for (int i = 0; i < in.length; i++) {
            k = k * 1103515245 + 12345;
            out[i] = (byte) (in[i] ^ (k >>> 16));
        }
        return Base64.getEncoder().encodeToString(out);
    }

    private AbstractInsnNode pushInt(int value) {
        if (value >= -1 && value <= 5) return new InsnNode(Opcodes.ICONST_0 + value);
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, value);
        if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, value);
        return new LdcInsnNode(value);
    }

    private void injectDecryptMethod(ClassNode cn, int classKey, ObfuscatorConfig.StringStrength strength) {
        boolean iface = (cn.access & Opcodes.ACC_INTERFACE) != 0;
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        String name = strength == ObfuscatorConfig.StringStrength.HEAVY ? DECRYPT_NAME_HEAVY : DECRYPT_NAME_STANDARD;
        String desc = strength == ObfuscatorConfig.StringStrength.HEAVY ? DECRYPT_DESC_HEAVY : DECRYPT_DESC_STANDARD;
        for (MethodNode existing : cn.methods) {
            if (existing.name.equals(name) && existing.desc.equals(desc)) return;
        }
        MethodNode mn = new MethodNode(access, name, desc, null, null);

        InsnList il = new InsnList();

        // byte[] data = Base64.getDecoder().decode(encoded);
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder",
                "()Ljava/util/Base64$Decoder;", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder", "decode",
                "(Ljava/lang/String;)[B", false));
        int dataVar = strength == ObfuscatorConfig.StringStrength.HEAVY ? 2 : 1;
        il.add(new VarInsnNode(Opcodes.ASTORE, dataVar));

        // int k = classKey [+ methodKey];
        il.add(new LdcInsnNode(classKey));
        if (strength == ObfuscatorConfig.StringStrength.HEAVY) {
            il.add(new VarInsnNode(Opcodes.ILOAD, 1));
            il.add(new InsnNode(Opcodes.IADD));
        }
        int kVar = dataVar + 1;
        il.add(new VarInsnNode(Opcodes.ISTORE, kVar));

        // for (int i = 0; i < data.length; i++)
        int iVar = kVar + 1;
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, iVar));

        org.objectweb.asm.tree.LabelNode loopStart = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode loopEnd = new org.objectweb.asm.tree.LabelNode();
        il.add(loopStart);
        il.add(new VarInsnNode(Opcodes.ILOAD, iVar));
        il.add(new VarInsnNode(Opcodes.ALOAD, dataVar));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        //   k = k * 1103515245 + 12345;
        il.add(new VarInsnNode(Opcodes.ILOAD, kVar));
        il.add(new LdcInsnNode(1103515245));
        il.add(new InsnNode(Opcodes.IMUL));
        il.add(new LdcInsnNode(12345));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new VarInsnNode(Opcodes.ISTORE, kVar));

        //   data[i] ^= (byte)(k >>> 16)
        il.add(new VarInsnNode(Opcodes.ALOAD, dataVar));
        il.add(new VarInsnNode(Opcodes.ILOAD, iVar));
        il.add(new InsnNode(Opcodes.DUP2));
        il.add(new InsnNode(Opcodes.BALOAD));
        il.add(new VarInsnNode(Opcodes.ILOAD, kVar));
        il.add(new IntInsnNode(Opcodes.BIPUSH, 16));
        il.add(new InsnNode(Opcodes.IUSHR));
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new InsnNode(Opcodes.I2B));
        il.add(new InsnNode(Opcodes.BASTORE));

        //   i++
        il.add(new org.objectweb.asm.tree.IincInsnNode(iVar, 1));
        il.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.GOTO, loopStart));
        il.add(loopEnd);

        // return new String(data, UTF_8)
        il.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, dataVar));
        il.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC,
                "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>",
                "([BLjava/nio/charset/Charset;)V", false));
        il.add(new InsnNode(Opcodes.ARETURN));

        mn.instructions = il;
        mn.maxLocals = iVar + 2;
        mn.maxStack = 6;
        cn.methods.add(mn);

        // Type annotation to mark as synthetic-generated
        Type.getType(desc); // explicit reference so compilers don't strip the import
    }
}
