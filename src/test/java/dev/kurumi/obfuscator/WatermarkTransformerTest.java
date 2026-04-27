package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import dev.kurumi.obfuscator.transformers.WatermarkTransformer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Confirms {@link dev.kurumi.obfuscator.transformers.WatermarkTransformer}:
 * <ol>
 *   <li>adds a private static final synthetic {@code String} field to
 *       every user class with the per-JAR prefix and {@code wm_} infix;</li>
 *   <li>the field's value is a non-empty XOR-encoded payload starting
 *       with the {@code WM1$} version tag (so a decoder can locate the
 *       watermark by linear scan over the constant pool);</li>
 *   <li>the field name is identical across all classes &mdash; a
 *       deobfuscator that drops "unused" fields will eliminate it
 *       uniformly, providing a tamper signal;</li>
 *   <li>the class still loads and its method still returns the right
 *       value.</li>
 * </ol>
 */
class WatermarkTransformerTest {

    @Test
    void embedsAndPreservesLoadability(@TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        writeJar(input, Map.of(
                "demo/User.class", buildSimple("demo/User"),
                "demo/Helper.class", buildSimple("demo/Helper")
        ));

        ObfuscatorConfig.Builder b = baselineDisabled();
        b.input = input;
        b.output = output;
        b.watermarkEnabled = true;

        new Obfuscator(b.build()).run();

        String userField = readWmField(output, "demo/User.class");
        String helperField = readWmField(output, "demo/Helper.class");

        // (1) Both classes have a watermark field with identical name.
        assertEquals(userField.split("=", 2)[0], helperField.split("=", 2)[0],
                "watermark field name must be uniform across all classes");

        // (2) Field name follows the documented prefix scheme.
        String fieldName = userField.split("=", 2)[0];
        assertTrue(fieldName.startsWith("$"),
                "watermark field name must start with '$' (synthetic prefix); got " + fieldName);
        assertTrue(fieldName.contains("wm_"),
                "watermark field name must contain 'wm_' infix; got " + fieldName);

        // (3) Both classes carry the SAME encoded watermark value
        //     (build-id is constant per build).
        String userValue = userField.split("=", 2)[1];
        String helperValue = helperField.split("=", 2)[1];
        assertEquals(userValue, helperValue,
                "watermark value must be the same across classes (per-build constant)");

        // (4) Value follows the WM1$ versioned envelope.
        assertTrue(userValue.startsWith("WM1$"),
                "watermark value must start with 'WM1$'; got " + userValue);
        assertTrue(userValue.length() > "WM1$".length() + 8,
                "watermark value must contain non-trivial payload; got " + userValue);

        // (5) Class still loads and answer() still returns 42.
        try (URLClassLoader cl = new URLClassLoader(
                new URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            Class<?> user = Class.forName("demo.User", true, cl);
            var m = user.getDeclaredMethod("answer");
            assertEquals(Integer.valueOf(42), m.invoke(null));
        }

        // (6) Round-trip: the embedded watermark must decode to a
        //     plausible build-id string. Without this, leak tracing
        //     is impossible -- which is the whole reason the
        //     watermark exists.
        String decoded = WatermarkTransformer.decodeWatermark(fieldName, userValue);
        assertNotNull(decoded, "decodeWatermark must succeed on its own output");
        assertTrue(decoded.startsWith("kurumi-build:"),
                "decoded watermark must be a kurumi-build:* identifier; got " + decoded);
        // Sanity: a wrong field name (different prefix) must NOT
        //        decode to the same plaintext, otherwise the
        //        per-prefix key derivation provides no isolation.
        String tamperedName = "$xxxxxwm_00000000";
        String wrongDecode = WatermarkTransformer.decodeWatermark(tamperedName, userValue);
        if (wrongDecode != null) {
            assertTrue(!decoded.equals(wrongDecode),
                    "decoder must produce different output for a different prefix");
        }
    }

    private static String readWmField(Path jar, String entryName) throws Exception {
        byte[] bytes;
        try (JarFile jf = new JarFile(jar.toFile())) {
            JarEntry je = jf.getJarEntry(entryName);
            assertNotNull(je, "missing entry: " + entryName);
            bytes = jf.getInputStream(je).readAllBytes();
        }
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, 0);
        for (FieldNode fn : cn.fields) {
            if (fn.name.contains("wm_")) {
                assertNotNull(fn.value, "watermark field must have a ConstantValue: " + fn.name);
                return fn.name + "=" + fn.value;
            }
        }
        throw new AssertionError("no wm_ field found in " + entryName);
    }

    private static ObfuscatorConfig.Builder baselineDisabled() {
        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.autoExempt = false;
        b.renamerEnabled = false;
        b.classExplodeEnabled = false;
        b.encryptedClassVaultEnabled = false;
        b.stringEncryptionEnabled = false;
        b.blobStringEnabled = false;
        b.flowEnabled = false;
        b.opaqueEnabled = false;
        b.numberEnabled = false;
        b.invokeDynamicEnabled = false;
        b.indyCallEnabled = false;
        b.indyFieldEnabled = false;
        b.junkCodeEnabled = false;
        b.bogusExceptionEnabled = false;
        b.stringConcatEnabled = false;
        b.classLiteralEnabled = false;
        b.memberShufflerEnabled = false;
        b.accessFlagsEnabled = false;
        b.localVarTableEnabled = false;
        b.localVarEnabled = false;
        b.cfgFlattenEnabled = false;
        b.fakeAnnotationsEnabled = false;
        b.sourceScrubEnabled = false;
        b.antiAgentEnabled = false;
        b.watermarkEnabled = false;
        b.verifyAfterEach = false;
        b.failOnVerifyError = false;
        return b;
    }

    private static byte[] buildSimple(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "answer", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(Opcodes.BIPUSH, 42);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void writeJar(Path output, Map<String, byte[]> entries) throws Exception {
        Files.createDirectories(output.getParent());
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(output))) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                jos.putNextEntry(new JarEntry(e.getKey()));
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
    }
}
