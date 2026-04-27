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
 *
 * <p>The per-byte cipher is delegated to {@link DecoderPolymorphism}: each
 * class is assigned one of {@link DecoderPolymorphism#VARIANT_COUNT} XOR
 * stream variants by hashing its internal name, so encrypting the same
 * plaintext under the same key in two different classes yields ciphertexts
 * that walk through different state machines (LCG, XORshift32, rotate-LCG,
 * plaintext-feedback LCG, index-keyed LCG). A reverse engineer who copies
 * one class's decoder body into a standalone tool will only decrypt that
 * class's strings; every other class needs a different decoder shape, not
 * just a different key.
 *
 * <p>Replaces the previous fixed {@code k = k * 1103515245 + 12345; out[i] =
 * in[i] ^ (k &gt;&gt;&gt; 16)} cipher, which was a single shared shape across
 * the entire JAR -- exactly the cross-class fingerprint
 * {@code DecoderPolymorphism} was introduced to remove.
 */
public class StringEncryptionTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(StringEncryptionTransformer.class);

    // The leading prefix is now per-JAR (computed once per pool by
    // {@link SyntheticNaming#prefix}). What was historically a fixed
    // "$obf" prefix gave reverse engineers a single literal to grep
    // across multiple obfuscator outputs; rotating it per-JAR removes
    // that cross-JAR fingerprint.
    private static final String DECRYPT_DESC_STANDARD = "(Ljava/lang/String;)Ljava/lang/String;";
    private static final String DECRYPT_DESC_HEAVY = "(Ljava/lang/String;I)Ljava/lang/String;";

    /**
     * Deterministic per-class 8-character alphanumeric suffix. Identical for
     * the same class on every obfuscator run, different for every class in
     * the same JAR. Prevents a reverse engineer from grepping for a known
     * symbol like {@code $obfD} to find every decryptor.
     */
    private static String decryptName(String internalName,
                                      ObfuscatorConfig.StringStrength strength,
                                      String prefix) {
        long h = 0xCBF29CE484222325L ^ (strength == ObfuscatorConfig.StringStrength.HEAVY ? 0xAL : 0x5L);
        for (int i = 0; i < internalName.length(); i++) {
            h ^= internalName.charAt(i);
            h *= 0x100000001B3L;
        }
        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        StringBuilder sb = new StringBuilder(prefix);
        for (int i = 0; i < 8; i++) {
            sb.append(alphabet[(int) ((h >>> (i * 8)) & 0x3F) % alphabet.length]);
            h = (h ^ (h >>> 7)) * 0xBF58476D1CE4E5B9L;
        }
        return sb.toString();
    }

    @Override
    public String name() {
        return "string-encryption";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        ObfuscatorConfig.StringStrength strength = ctx.config().stringStrength();
        int classesTouched = 0;
        int stringsEncrypted = 0;
        final String pfx = SyntheticNaming.prefix(pool);

        // Per-pool name of the {@code StackProbe} helper class. It is
        // generated lazily and only added to the pool if at least one
        // user class actually receives an encrypted string -- otherwise
        // we would gratuitously perturb downstream random-seeded
        // transformers (e.g. {@code JunkCodeInjector}) which fingerprint
        // the entire pool.
        //
        // Per-class decryptors call its {@code checkCaller} method to
        // read the actual caller's binary class name from the stack
        // frame (frame [2]: probe → decryptor → caller). The encoder
        // seeds with the owning class's name hashCode, so a legitimate
        // INVOKESTATIC from inside that class agrees on the seed; a
        // reflective {@code Method.invoke} produces a
        // {@code jdk.internal.reflect.*} caller string with a different
        // hashCode, which desynchronises the XOR stream and yields
        // garbage. This is the load-bearing change that breaks "rip the
        // decryptor and call it via reflection" attacks.
        String probeName = pfx + "StackProbe_"
                + Integer.toHexString(pool.size() ^ 0x7E517A07);

        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) continue;
            if (cn.name.endsWith("/package-info")) continue;
            // The probe class itself has no strings to encrypt; skip.
            if (cn.name.equals(probeName)) continue;

            int classKey = deriveClassKey(cn.name);
            // Runtime-bound part: encoder mixes the OWNING class's
            // dot-name hashCode into the seed; the decoder reads the
            // actual stack caller via {@link #probeName}. For
            // legitimate calls the caller IS the owning class, so
            // hashes agree. Reflection invocation puts
            // {@code MethodAccessorImpl} on the stack instead, hash
            // differs, XOR desynchronises, decode produces garbage.
            int runtimeBinding = cn.name.replace('/', '.').hashCode();
            int variant = DecoderPolymorphism.variantFor(cn.name);
            String decryptName = decryptName(cn.name, strength, pfx);
            boolean classTouched = false;

            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals(decryptName)) continue;

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
                    int perCallSalt = strength == ObfuscatorConfig.StringStrength.HEAVY
                            ? java.util.concurrent.ThreadLocalRandom.current().nextInt() : 0;
                    String encoded = encode(original, classKey + methodKey + perCallSalt + runtimeBinding, variant);
                    ldc.cst = encoded;
                    InsnList replacement = new InsnList();
                    String desc = strength == ObfuscatorConfig.StringStrength.HEAVY ? DECRYPT_DESC_HEAVY : DECRYPT_DESC_STANDARD;
                    if (strength == ObfuscatorConfig.StringStrength.HEAVY) {
                        // pass (methodKey + perCallSalt) so identical strings in the same
                        // method still encode to distinct ciphertexts
                        replacement.add(pushInt(methodKey + perCallSalt));
                    }
                    replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name,
                            decryptName, desc, (cn.access & Opcodes.ACC_INTERFACE) != 0));
                    insns.insert(ldc, replacement);
                    classTouched = true;
                    stringsEncrypted++;
                }
            }

            if (classTouched) {
                injectDecryptMethod(cn, classKey, strength, decryptName, variant, probeName);
                classesTouched++;
            }
        }
        // Lazily emit the probe class only if any decryptor was
        // actually generated. Skipping the probe when no class needed
        // encryption keeps the pool size identical for downstream
        // random-seeded transformers (e.g. JunkCodeInjector
        // fingerprints the whole pool).
        if (classesTouched > 0) {
            ClassNode probe = buildStackProbeClass(probeName);
            pool.addClass(probe);
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

    private String encode(String original, int key, int variant) {
        byte[] in = original.getBytes(StandardCharsets.UTF_8);
        byte[] out = DecoderPolymorphism.xorByteStream(in, key, variant);
        return Base64.getEncoder().encodeToString(out);
    }

    private AbstractInsnNode pushInt(int value) {
        if (value >= -1 && value <= 5) return new InsnNode(Opcodes.ICONST_0 + value);
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, value);
        if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, value);
        return new LdcInsnNode(value);
    }

    private void injectDecryptMethod(ClassNode cn, int classKey, ObfuscatorConfig.StringStrength strength,
                                     String name, int variant, String probeOwner) {
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
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
        // k += $<pfx>StackProbe_<hash>.checkCaller().hashCode();
        // Runtime-bound part of the key derived from the ACTUAL
        // stack caller of this decryptor (not from this class's own
        // name -- that would also be "correct" for reflective
        // invocation, since reflection still locates the decryptor
        // method inside this class). The probe walks the stack two
        // frames up (probe -> decryptor -> caller) and returns the
        // caller's binary class name. The encoder seeded the XOR
        // stream with cn.name.replace('/', '.').hashCode(), which
        // for a legitimate INVOKESTATIC from inside this class is
        // exactly what the probe returns. A Method.invoke caller
        // resolves to a jdk.internal.reflect.* class whose name
        // hashes differently -- the XOR stream desynchronises and
        // the decryptor returns garbage instead of plaintext.
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, probeOwner,
                "checkCaller", "()Ljava/lang/String;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "hashCode", "()I", false));
        il.add(new InsnNode(Opcodes.IADD));
        int kVar = dataVar + 1;
        il.add(new VarInsnNode(Opcodes.ISTORE, kVar));

        // for (int i = 0; i < data.length; i++)
        int iVar = kVar + 1;
        int plainVar = iVar + 1;
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, iVar));

        org.objectweb.asm.tree.LabelNode loopStart = new org.objectweb.asm.tree.LabelNode();
        org.objectweb.asm.tree.LabelNode loopEnd = new org.objectweb.asm.tree.LabelNode();
        il.add(loopStart);
        il.add(new VarInsnNode(Opcodes.ILOAD, iVar));
        il.add(new VarInsnNode(Opcodes.ALOAD, dataVar));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // plain = (data[i] & 0xFF) ^ mask(k, i)
        il.add(new VarInsnNode(Opcodes.ALOAD, dataVar));
        il.add(new VarInsnNode(Opcodes.ILOAD, iVar));
        il.add(new InsnNode(Opcodes.BALOAD));
        il.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
        il.add(new InsnNode(Opcodes.IAND));
        DecoderPolymorphism.emitMask(il, kVar, iVar, variant);
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new VarInsnNode(Opcodes.ISTORE, plainVar));

        // data[i] = (byte) plain
        il.add(new VarInsnNode(Opcodes.ALOAD, dataVar));
        il.add(new VarInsnNode(Opcodes.ILOAD, iVar));
        il.add(new VarInsnNode(Opcodes.ILOAD, plainVar));
        il.add(new InsnNode(Opcodes.I2B));
        il.add(new InsnNode(Opcodes.BASTORE));

        // k = keyUpdate(k, i, plain, variant)
        DecoderPolymorphism.emitKeyUpdate(il, kVar, iVar, plainVar, variant);

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
        mn.maxLocals = plainVar + 1;
        mn.maxStack = 6;
        cn.methods.add(mn);

        // Type annotation to mark as synthetic-generated
        Type.getType(desc); // explicit reference so compilers don't strip the import
    }

    /**
     * Builds the per-pool {@code StackProbe} helper class.
     *
     * <p>Exposes a single static method
     * {@code public static String checkCaller()} that returns the
     * binary class name of the frame two levels up the call stack
     * (probe → decryptor → caller). Computed via
     * {@code new Throwable().getStackTrace()} to avoid the
     * lambda boilerplate that {@code StackWalker.walk} would
     * require in plain ASM. {@code Throwable.getStackTrace()} is
     * heavier than {@code StackWalker} but the call rate is bounded
     * by {@code LDC} sites, which is rare on hot paths and is
     * dwarfed by the surrounding XOR + Base64 work.
     */
    private static ClassNode buildStackProbeClass(String internalName) {
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V11;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = internalName;
        cn.superName = "java/lang/Object";
        cn.interfaces = new java.util.ArrayList<>();
        cn.fields = new java.util.ArrayList<>();
        cn.methods = new java.util.ArrayList<>();

        MethodNode init = new MethodNode(
                Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
        InsnList ii = new InsnList();
        ii.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ii.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ii.add(new InsnNode(Opcodes.RETURN));
        init.instructions = ii;
        init.maxLocals = 1;
        init.maxStack = 1;
        cn.methods.add(init);

        MethodNode probe = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                "checkCaller", "()Ljava/lang/String;", null, null);
        InsnList p = new InsnList();
        // StackTraceElement[] trace = new Throwable().getStackTrace();
        p.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.NEW, "java/lang/Throwable"));
        p.add(new InsnNode(Opcodes.DUP));
        p.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Throwable", "<init>", "()V", false));
        p.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Throwable", "getStackTrace",
                "()[Ljava/lang/StackTraceElement;", false));
        p.add(new VarInsnNode(Opcodes.ASTORE, 0));

        // if (trace.length < 3) return "";
        p.add(new VarInsnNode(Opcodes.ALOAD, 0));
        p.add(new InsnNode(Opcodes.ARRAYLENGTH));
        p.add(new IntInsnNode(Opcodes.BIPUSH, 3));
        org.objectweb.asm.tree.LabelNode hasFrame = new org.objectweb.asm.tree.LabelNode();
        p.add(new org.objectweb.asm.tree.JumpInsnNode(Opcodes.IF_ICMPGE, hasFrame));
        p.add(new LdcInsnNode(""));
        p.add(new InsnNode(Opcodes.ARETURN));

        // return trace[2].getClassName();
        p.add(hasFrame);
        p.add(new VarInsnNode(Opcodes.ALOAD, 0));
        p.add(new InsnNode(Opcodes.ICONST_2));
        p.add(new InsnNode(Opcodes.AALOAD));
        p.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StackTraceElement", "getClassName",
                "()Ljava/lang/String;", false));
        p.add(new InsnNode(Opcodes.ARETURN));
        probe.instructions = p;
        probe.maxLocals = 1;
        probe.maxStack = 3;
        cn.methods.add(probe);

        return cn;
    }
}
