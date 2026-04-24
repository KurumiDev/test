package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Confirms {@link dev.kurumi.obfuscator.transformers.FakeAnnotationTransformer}:
 * <ol>
 *   <li>adds synthetic runtime-retained annotation classes to the
 *       output JAR (e.g. {@code io/kurumi/protect/License.class});</li>
 *   <li>injects at least one misleading annotation on the processed
 *       target class;</li>
 *   <li>keeps the class loadable and its method callable (no verify
 *       errors, no {@code AnnotationFormatError}).</li>
 * </ol>
 */
class FakeAnnotationTest {

    @Test
    void injectsAndPreservesLoadability(@TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        writeJar(input, Map.of(
                "demo/User.class", buildSimple("demo/User")
        ));

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.autoExempt = false;
        // Turn off everything so we test fake-annotations in isolation.
        b.renamerEnabled = false;
        b.classExplodeEnabled = false;
        b.encryptedClassVaultEnabled = false;
        b.stringEncryptionEnabled = false;
        b.blobStringEnabled = false;
        b.flowEnabled = false;
        b.opaqueEnabled = false;
        b.numberEnabled = false;
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
        b.fakeAnnotationsEnabled = true;
        b.verifyAfterEach = false;
        b.failOnVerifyError = false;

        new Obfuscator(b.build()).run();

        // (1) Synthetic annotation classes must exist in the jar.
        Set<String> entries = new HashSet<>();
        try (JarFile jf = new JarFile(output.toFile())) {
            jf.stream().forEach(e -> entries.add(e.getName()));
        }
        assertTrue(entries.contains("io/kurumi/protect/License.class"));
        assertTrue(entries.contains("io/kurumi/protect/AntiCheat.class"));
        assertTrue(entries.contains("io/kurumi/protect/SecurityReview.class"));
        assertTrue(entries.contains("io/kurumi/protect/AuditTrail.class"));

        // (2) The target class must now carry at least one misleading
        //     annotation reference (lombok.Generated is injected on
        //     every class unconditionally, so assert on its presence).
        byte[] userBytes;
        try (JarFile jf = new JarFile(output.toFile())) {
            JarEntry je = jf.getJarEntry("demo/User.class");
            assertNotNull(je);
            userBytes = jf.getInputStream(je).readAllBytes();
        }
        ClassNode cn = new ClassNode();
        new ClassReader(userBytes).accept(cn, 0);
        Set<String> descs = new HashSet<>();
        for (AnnotationNode a : safeList(cn.visibleAnnotations)) descs.add(a.desc);
        for (AnnotationNode a : safeList(cn.invisibleAnnotations)) descs.add(a.desc);
        assertTrue(descs.contains("Llombok/Generated;"),
                "class must be decorated with @lombok.Generated marker");

        // (3) Class still loads and method still returns the right value.
        try (URLClassLoader cl = new URLClassLoader(
                new URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            Class<?> user = Class.forName("demo.User", true, cl);
            var m = user.getDeclaredMethod("answer");
            assertEquals(Integer.valueOf(42), m.invoke(null));
        }
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

    private static <T> List<T> safeList(List<T> xs) {
        return xs == null ? List.of() : xs;
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
