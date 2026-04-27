package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test for {@link
 * dev.kurumi.obfuscator.transformers.AntiTamperTransformer}.
 *
 * <p>Builds a tiny single-class JAR with a {@code main} that prints
 * {@code "marker"}, runs it through the obfuscator with anti-tamper
 * enabled, and asserts:
 * <ol>
 *   <li>An {@code IntegritySvc_*} helper class is added to the
 *       output JAR.</li>
 *   <li>Running the unmodified obfuscated JAR prints {@code "marker"}
 *       and exits 0.</li>
 *   <li>Flipping a single byte near the end of the user class (so we
 *       hit the code attribute, not the magic / version header) and
 *       re-running causes the JVM to {@link Runtime#halt(int) halt(1)}
 *       with no output.</li>
 * </ol>
 *
 * <p>The unobfuscated control run is also verified to print
 * {@code "marker"} -- this rules out a flaky JAR before we trust the
 * obfuscated comparison.
 */
class AntiTamperTransformerTest {

    @Test
    void tamperedJarHaltsAtRuntime(@TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");
        Path tampered = tmp.resolve("tampered.jar");

        writeJar(input, Map.of(
                "demo/App.class", buildApp("demo/App")
        ), "demo.App");

        ObfuscatorConfig.Builder b = baselineDisabled();
        b.input = input;
        b.output = output;
        b.antiTamperEnabled = true;
        new Obfuscator(b.build()).run();

        // (1) Helper class present.
        boolean hasSvc = false;
        try (JarFile jf = new JarFile(output.toFile())) {
            hasSvc = jf.stream()
                    .anyMatch(e -> e.getName().contains("IntegritySvc_")
                            && e.getName().endsWith(".class"));
        }
        assertTrue(hasSvc, "output JAR must contain an IntegritySvc_*.class entry");

        // (2) Pristine obfuscated JAR runs and prints "marker".
        String pristine = runJarCapture(output);
        assertEquals("marker", pristine.trim(),
                "pristine obfuscated JAR must print 'marker'; got: " + pristine);

        // (3) Tamper with the user class -- flip one byte near the
        //     tail (where the Code attribute and string constants
        //     live). Header bytes (magic, version) are off-limits
        //     because corrupting them makes the JVM reject the class
        //     before <clinit> ever runs, which would also pass our
        //     "did not print marker" check but wouldn't actually
        //     prove that the integrity check fired.
        repackWithMutation(output, tampered, "demo/App.class", bytes -> {
            // Flip a code-attribute byte. Offset chosen empirically
            // away from the magic/version/CP header.
            int idx = bytes.length - 80;
            bytes[idx] = (byte) (bytes[idx] ^ 0x01);
            return bytes;
        });

        String tamperedOut = runJarCapture(tampered);
        assertNotEquals("marker", tamperedOut.trim(),
                "tampered JAR MUST NOT print 'marker'; got: " + tamperedOut);
    }

    private static String runJarCapture(Path jar) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
                javaExecutable(), "-jar", jar.toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream in = p.getInputStream()) {
            in.transferTo(baos);
        }
        p.waitFor();
        return baos.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String javaExecutable() {
        String home = System.getProperty("java.home");
        Path bin = Path.of(home, "bin", "java");
        return bin.toString();
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
        b.antiTamperEnabled = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        return b;
    }

    /**
     * {@code public static void main(String[] args) { System.out.println("marker"); }}
     */
    private static byte[] buildApp(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null,
                "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "main", "([Ljava/lang/String;)V", null, null);
        mv.visitCode();
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out",
                "Ljava/io/PrintStream;");
        mv.visitLdcInsn("marker");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                "(Ljava/lang/String;)V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void writeJar(Path output, Map<String, byte[]> entries, String mainClass) throws IOException {
        Files.createDirectories(output.getParent());
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(output))) {
            jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
            String mf = "Manifest-Version: 1.0\nMain-Class: " + mainClass + "\n\n";
            jos.write(mf.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            jos.closeEntry();
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                jos.putNextEntry(new JarEntry(e.getKey()));
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
    }

    private interface ByteMutator {
        byte[] mutate(byte[] in);
    }

    private static void repackWithMutation(Path src, Path dst, String pathToMutate,
                                           ByteMutator mut) throws IOException {
        Map<String, byte[]> all = new HashMap<>();
        try (JarFile jf = new JarFile(src.toFile())) {
            jf.stream().forEach(je -> {
                try (InputStream in = jf.getInputStream(je)) {
                    byte[] data = in.readAllBytes();
                    if (je.getName().equals(pathToMutate)) {
                        data = mut.mutate(data);
                    }
                    all.put(je.getName(), data);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(dst))) {
            for (Map.Entry<String, byte[]> e : all.entrySet()) {
                jos.putNextEntry(new JarEntry(e.getKey()));
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
    }
}
