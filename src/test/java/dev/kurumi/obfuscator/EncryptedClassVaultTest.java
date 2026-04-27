package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.HashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the full encrypted-class-vault pipeline on a synthetic JAR
 * whose sole user class references a synthetic worker (named after one
 * of the class-exploder worker roots so the vault transformer is
 * willing to encrypt it). After obfuscation the worker class file must
 * have been removed from the JAR, a {@code META-INF/obf/...} payload
 * must exist, and loading the user class under a fresh class loader
 * must succeed &mdash; proving the vault's {@code <clinit>} decrypted
 * and re-defined the worker before the caller needed it.
 */
class EncryptedClassVaultTest {

    @Test
    void workerIsEvictedAndRestoredAtRuntime(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        byte[] workerBytes = buildWorker("demo/LicenseGuard_feedf00d");
        byte[] userBytes = buildUser("demo/User", "demo/LicenseGuard_feedf00d");

        Map<String, byte[]> entries = new HashMap<>();
        entries.put("demo/LicenseGuard_feedf00d.class", workerBytes);
        entries.put("demo/User.class", userBytes);
        writeJar(input, entries);

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.autoExempt = false;
        b.renamerEnabled = false;
        b.classExplodeEnabled = false;
        b.encryptedClassVaultEnabled = true;
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
        b.verifyAfterEach = false;
        b.failOnVerifyError = false;

        new Obfuscator(b.build()).run();

        boolean workerInJar = false;
        String vaultName = null;
        boolean payloadPresent = false;
        try (JarFile jf = new JarFile(output.toFile())) {
            var e = jf.entries();
            while (e.hasMoreElements()) {
                JarEntry je = e.nextElement();
                if ("demo/LicenseGuard_feedf00d.class".equals(je.getName())) workerInJar = true;
                // Vault classes have the per-JAR synthetic prefix
                // ($ + 5 lowercase alphanumeric chars) followed by
                // "ClassVault_<id>". We don't know the prefix here
                // (it's a function of the JAR contents), so detect by
                // the stable infix.
                if (je.getName().startsWith("demo/$") && je.getName().contains("ClassVault_")
                        && je.getName().endsWith(".class")) {
                    vaultName = je.getName().substring(0, je.getName().length() - ".class".length()).replace('/', '.');
                }
                if (je.getName().startsWith("META-INF/obf/demo/") && je.getName().endsWith(".bin")) {
                    payloadPresent = true;
                }
            }
        }
        assertFalse(workerInJar, "worker class should have been moved out of the JAR");
        assertNotNull(vaultName, "vault class should have been emitted");
        assertTrue(payloadPresent, "encrypted payload resource should have been emitted");

        try (URLClassLoader cl = new URLClassLoader(
                new URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            // Load the user class — its <clinit> forces the vault to load, which
            // defines the encrypted worker. Then invoke a method that calls
            // the worker statically: the JVM must resolve the worker without
            // finding its .class in the JAR.
            Class<?> user = Class.forName("demo.User", true, cl);
            var m = user.getDeclaredMethod("entry");
            Object result = m.invoke(null);
            assertEquals(Integer.valueOf(42), result,
                    "encrypted worker's static method must execute correctly after vault <clinit>");
        }
    }

    private static byte[] buildUser(String internal, String workerInternal) {
        org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES | org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
        cw.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC, internal, null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "entry", "()Ljava/lang/Integer;", null, null);
        mv.visitCode();
        mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC,
                workerInternal, "value", "()I", false);
        mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC,
                "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
        mv.visitInsn(org.objectweb.asm.Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] buildWorker(String internal) {
        org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES | org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
        cw.visit(org.objectweb.asm.Opcodes.V17,
                org.objectweb.asm.Opcodes.ACC_PUBLIC, internal, null, "java/lang/Object", null);
        org.objectweb.asm.MethodVisitor mv = cw.visitMethod(
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_STATIC,
                "value", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 42);
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void writeJar(Path output, Map<String, byte[]> entries) throws Exception {
        Files.createDirectories(output.getParent());
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(output))) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                JarEntry je = new JarEntry(e.getKey());
                jos.putNextEntry(je);
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
    }
}
