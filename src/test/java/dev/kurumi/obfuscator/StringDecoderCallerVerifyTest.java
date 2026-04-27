package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Adversarial test for {@link
 * dev.kurumi.obfuscator.transformers.StringEncryptionTransformer}'s
 * stack-probe based caller verification.
 *
 * <p>Threat model: a deobfuscator inspects the obfuscated JAR, finds
 * the synthetic decryptor method (e.g. {@code $obfABCDEFGH}) on each
 * class, and invokes it reflectively to recover plaintext for every
 * encrypted LDC site without touching the surrounding bytecode. This
 * is the standard "rip the decryptor" attack used by tools such as
 * the {@code java-deobfuscator} project's
 * {@code GeneralStringEncryptionTransformer}.
 *
 * <p>We assert two things:
 * <ol>
 *   <li>Legitimate in-bytecode invocation -- via {@code Class.forName}
 *       + a public method that internally LDC-decrypts a constant --
 *       returns the original plaintext.</li>
 *   <li>Reflective invocation of the same decryptor on the same
 *       ciphertext does <b>not</b> return the plaintext. The XOR
 *       stream is keyed on the actual stack caller's class name, so
 *       a {@code Method.invoke} caller (whose binary class name is
 *       under {@code jdk.internal.reflect.*}) hashes differently
 *       and the decoder produces garbage.</li>
 * </ol>
 *
 * <p>The probe helper class itself is also expected to appear in the
 * output JAR with the per-JAR synthetic prefix and the
 * {@code StackProbe_} infix.
 */
class StringDecoderCallerVerifyTest {

    @Test
    void reflectiveDecryptorInvocationProducesGarbage(@TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        writeJar(input, Map.of(
                "demo/Greeter.class", buildGreeter("demo/Greeter")
        ));

        ObfuscatorConfig.Builder b = baselineDisabled();
        b.input = input;
        b.output = output;
        b.stringEncryptionEnabled = true;
        b.stringStrength = ObfuscatorConfig.StringStrength.STANDARD;
        new Obfuscator(b.build()).run();

        // (1) The probe helper class must appear.
        Set<String> entries = new HashSet<>();
        try (JarFile jf = new JarFile(output.toFile())) {
            jf.stream().forEach(e -> entries.add(e.getName()));
        }
        boolean hasProbe = entries.stream()
                .anyMatch(e -> e.contains("StackProbe_") && e.endsWith(".class"));
        assertTrue(hasProbe, "output JAR must contain a *StackProbe_*.class entry; got " + entries);

        // (2) Legitimate in-bytecode call returns the plaintext.
        try (URLClassLoader cl = new URLClassLoader(
                new URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            Class<?> greeter = Class.forName("demo.Greeter", true, cl);
            Method greet = greeter.getDeclaredMethod("greet");
            Object result = greet.invoke(null);
            assertEquals("hello-world", result,
                    "in-bytecode decryption must round-trip to the original plaintext");

            // (3) Reflective invocation of the decryptor on the same
            //     ciphertext must NOT return the plaintext. We don't
            //     know the decryptor name a priori; find it by
            //     looking for a synthetic public static String(String)
            //     method whose name is not "greet".
            Method decryptor = null;
            for (Method m : greeter.getDeclaredMethods()) {
                if (!m.getReturnType().equals(String.class)) continue;
                if (m.getParameterCount() != 1) continue;
                if (!m.getParameterTypes()[0].equals(String.class)) continue;
                if (m.getName().equals("greet")) continue;
                if ((m.getModifiers() & java.lang.reflect.Modifier.STATIC) == 0) continue;
                decryptor = m;
                break;
            }
            assertNotNull(decryptor, "must locate a static String(String) decryptor candidate");

            // We need the encoded form of "hello-world" stored on the
            // class. The simplest way is to enumerate every LDC
            // constant in the class file and try decrypting each.
            byte[] greeterBytes;
            try (JarFile jf = new JarFile(output.toFile())) {
                JarEntry je = jf.getJarEntry("demo/Greeter.class");
                assertNotNull(je);
                greeterBytes = jf.getInputStream(je).readAllBytes();
            }
            org.objectweb.asm.tree.ClassNode cn = new org.objectweb.asm.tree.ClassNode();
            new org.objectweb.asm.ClassReader(greeterBytes).accept(cn, 0);

            String foundEncoded = null;
            for (org.objectweb.asm.tree.MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                for (org.objectweb.asm.tree.AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (insn instanceof org.objectweb.asm.tree.LdcInsnNode ldc
                            && ldc.cst instanceof String s
                            && !s.isEmpty()) {
                        foundEncoded = s;
                        break;
                    }
                }
                if (foundEncoded != null) break;
            }
            assertNotNull(foundEncoded,
                    "must find at least one LDC string in the obfuscated greeter class");

            String reflectiveResult;
            try {
                reflectiveResult = (String) decryptor.invoke(null, foundEncoded);
            } catch (Throwable t) {
                // Throwing is also an acceptable form of "didn't
                // return plaintext"; we treat it as an inconclusive
                // pass (the attacker still doesn't get plaintext).
                reflectiveResult = "<<threw " + t.getClass().getSimpleName() + ">>";
            }
            assertNotEquals("hello-world", reflectiveResult,
                    "reflective decryptor invocation MUST NOT recover the plaintext; "
                            + "got: " + reflectiveResult);
        }
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
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        return b;
    }

    /**
     * {@code public static String greet() { return "hello-world"; }}
     * The single LDC string is what the obfuscator will encrypt.
     */
    private static byte[] buildGreeter(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null,
                "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "greet", "()Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitLdcInsn("hello-world");
        mv.visitInsn(Opcodes.ARETURN);
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
