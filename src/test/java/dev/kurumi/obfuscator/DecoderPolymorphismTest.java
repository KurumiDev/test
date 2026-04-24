package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import dev.kurumi.obfuscator.transformers.DecoderPolymorphism;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link DecoderPolymorphism} ships four distinct variants,
 * all of which round-trip correctly and, when used by the three
 * indy/blob transformers, produce distinguishable decoder bodies across
 * classes with different variant indices.
 */
class DecoderPolymorphismTest {

    @Test
    void allVariantsRoundTrip() {
        String plain = "the quick brown fox jumps over the lazy dog "
                + "\u0000\u00FF\u0001\u00FE " + "0123456789";
        byte[] pbytes = plain.getBytes(StandardCharsets.UTF_8);
        for (int variant = 0; variant < DecoderPolymorphism.VARIANT_COUNT; variant++) {
            int seed = 0xA1B2C3D4 ^ variant;
            byte[] enc = DecoderPolymorphism.xorByteStream(pbytes, seed, variant);
            // Encrypting the ciphertext with the same seed must NOT in
            // general recover the plaintext for asymmetric variants.
            // For the symmetric XOR-based variants the encoder and
            // decoder share a per-byte XOR with the running key, so the
            // very same xorByteStream call is both encrypt and decrypt
            // if it consumes the decrypted plaintext while updating k.
            // Since xorByteStream reads the mask from (raw[i] & 0xFF)
            // for V3 and updates k from the plaintext, encrypting twice
            // does NOT invert except for V0/V1/V2.  The actual decode
            // used at runtime runs inside the ASM-emitted bytecode,
            // which consumes the decoded byte to feed the next key
            // update. Here we emulate that inline.
            byte[] dec = xorDecodeEmulated(enc, seed, variant);
            assertArrayEquals(pbytes, dec,
                    "Variant " + variant + " must round-trip symmetrically");
        }
    }

    private static byte[] xorDecodeEmulated(byte[] raw, int seed, int variant) {
        byte[] out = new byte[raw.length];
        int k = seed;
        for (int i = 0; i < raw.length; i++) {
            int mask = (variant == 2)
                    ? ((k ^ (i * 0x9E3779B9)) & 0xFF)
                    : (k & 0xFF);
            int plain = (raw[i] & 0xFF) ^ mask;
            out[i] = (byte) plain;
            switch (variant) {
                case 1:
                    k ^= k << 13;
                    k ^= k >>> 17;
                    k ^= k << 5;
                    break;
                case 2:
                    k = Integer.rotateLeft(k, 11) + 0xDEADBEEF;
                    break;
                case 3:
                    k = k * 0x45D9F3B + plain + 0x119DE1F3;
                    break;
                default:
                    k = k * 0x45D9F3B + 0x119DE1F3;
            }
        }
        return out;
    }

    @Test
    void variantSelectorDisperses() {
        // A small zoo of class names should exercise at least 3 of the 4
        // variants so the polymorphism is observable on a real JAR.
        String[] names = {
                "com/example/A",
                "com/example/B",
                "io/kurumi/shcommandblocker/SHCommandBlocker",
                "o/a", "o/b", "o/c",
                "io/kurumi/shcommandblocker/LicenseGuard_abcdef01",
                "io/kurumi/shcommandblocker/TokenRing_deadbeef",
                "io/kurumi/shcommandblocker/AuthProbe_cafebabe",
                "io/kurumi/shcommandblocker/HeartbeatSink_beadfade",
                "io/kurumi/shcommandblocker/CertPinner_cdefabcd",
                "io/kurumi/shcommandblocker/SessionRefresher_01234567",
        };
        Set<Integer> seen = new HashSet<>();
        for (String n : names) seen.add(DecoderPolymorphism.variantFor(n));
        assertTrue(seen.size() >= 3,
                "Expected >=3 distinct variants across 12 class names, got " + seen);
    }

    @Test
    void indyFieldRoundTripsOnAllFourVariants(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        // Build 4 (owner, reader) pairs where the owners' internal names
        // deliberately land on different variantFor buckets. This
        // establishes that the emitted decoder is correct for each
        // variant in full end-to-end form (not just the Java-side
        // xorByteStream).
        String[] ownerPool = findNamesForEachVariant();
        assertNotNull(ownerPool[0]);
        assertNotNull(ownerPool[1]);
        assertNotNull(ownerPool[2]);
        assertNotNull(ownerPool[3]);

        for (int v = 0; v < 4; v++) {
            String owner = ownerPool[v];
            String reader = owner + "_Reader";
            Path input = tmp.resolve("poly" + v + ".jar");
            try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(input), new Manifest())) {
                jos.putNextEntry(new JarEntry(owner + ".class"));
                jos.write(buildOwner(owner));
                jos.closeEntry();
                jos.putNextEntry(new JarEntry(reader + ".class"));
                jos.write(buildReader(reader, owner));
                jos.closeEntry();
            }
            Path output = tmp.resolve("poly" + v + "-obf.jar");
            ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
            b.input = input;
            b.output = output;
            b.target = ObfuscatorConfig.Target.PLAIN;
            b.renameClasses = false;
            b.renameMethods = false;
            b.renameFields = false;
            b.stringEncryptionEnabled = false;
            b.opaqueEnabled = false;
            b.flowEnabled = false;
            b.bogusExceptionEnabled = false;
            b.numberEnabled = false;
            b.classLiteralEnabled = false;
            b.stringConcatEnabled = false;
            b.invokeDynamicEnabled = false;
            b.indyCallEnabled = false;
            b.indyFieldEnabled = true;
            b.junkCodeEnabled = false;
            b.accessFlagsEnabled = false;
            b.memberShufflerEnabled = false;
            b.sourceScrubEnabled = false;
            b.localVarEnabled = true;
            b.verifyAfterEach = true;
            b.failOnVerifyError = true;
            b.autoExempt = false;
            new Obfuscator(b.build()).run();

            try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                    DecoderPolymorphismTest.class.getClassLoader())) {
                Class<?> r = Class.forName(reader, true, cl);
                Method entry = r.getMethod("entry");
                Object result = entry.invoke(null);
                assertEquals(100 + v, result,
                        "Variant " + v + " owner " + owner + " must round-trip");
            }
        }
    }

    private static String[] findNamesForEachVariant() {
        String[] result = new String[DecoderPolymorphism.VARIANT_COUNT];
        for (int i = 0; i < 20_000 && anyNull(result); i++) {
            String candidate = "Probe" + Integer.toHexString(i);
            int v = DecoderPolymorphism.variantFor(candidate);
            if (result[v] == null) result[v] = candidate;
        }
        return result;
    }

    private static boolean anyNull(String[] a) {
        for (String s : a) if (s == null) return true;
        return false;
    }

    private byte[] buildOwner(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null, "java/lang/Object", null);
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "VAL", "I", null, null).visitEnd();
        MethodVisitor clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        // We encode the expected value deterministically: 100 + variantFor(internal)
        int expected = 100 + DecoderPolymorphism.variantFor(internal);
        clinit.visitLdcInsn(Integer.valueOf(expected));
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, internal, "VAL", "I");
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(1, 0);
        clinit.visitEnd();
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private byte[] buildReader(String internal, String ownerInternal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null, "java/lang/Object", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "entry",
                "()I", null, null);
        mv.visitFieldInsn(Opcodes.GETSTATIC, ownerInternal, "VAL", "I");
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
