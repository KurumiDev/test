package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Confirms {@link dev.kurumi.obfuscator.transformers.AntiAgentTransformer}:
 * <ol>
 *   <li>emits a synthetic guard class into the output JAR with the
 *       per-JAR synthetic prefix and the {@code AgentGuard_} infix.</li>
 *   <li>injects an {@code INVOKESTATIC <guard>.check()V} call at the
 *       very start of every user class's {@code <clinit>}.</li>
 *   <li>keeps the user class loadable and its method invocable when
 *       no debugger / agent is attached (clean classloader).</li>
 * </ol>
 *
 * <p>End-to-end behaviour under {@code -javaagent:} is exercised by
 * the obfuscator runtime itself rather than this unit test &mdash;
 * spawning a child JVM with {@code -javaagent:} from inside JUnit
 * is fragile (the test harness itself runs under a JVM agent in many
 * IDEs). We assert that the call is wired up correctly here and rely
 * on the integration JAR + sample manual run for runtime proof.
 */
class AntiAgentTransformerTest {

    @Test
    void instrumentsAndPreservesLoadability(@TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        writeJar(input, Map.of(
                "demo/User.class", buildSimple("demo/User")
        ));

        ObfuscatorConfig.Builder b = baselineDisabled();
        b.input = input;
        b.output = output;
        b.antiAgentEnabled = true;

        new Obfuscator(b.build()).run();

        // (1) Output JAR contains a guard class whose name has the
        //     expected infix.
        Set<String> entries = new HashSet<>();
        try (JarFile jf = new JarFile(output.toFile())) {
            jf.stream().forEach(e -> entries.add(e.getName()));
        }
        String guardEntry = entries.stream()
                .filter(e -> e.contains("AgentGuard_") && e.endsWith(".class"))
                .findFirst()
                .orElse(null);
        assertNotNull(guardEntry, "output JAR must contain an *AgentGuard_*.class entry; got " + entries);
        String guardInternal = guardEntry.substring(0, guardEntry.length() - ".class".length());

        // (2) The user class's <clinit> begins with a call to the guard.
        byte[] userBytes;
        try (JarFile jf = new JarFile(output.toFile())) {
            JarEntry je = jf.getJarEntry("demo/User.class");
            assertNotNull(je);
            userBytes = jf.getInputStream(je).readAllBytes();
        }
        ClassNode cn = new ClassNode();
        new ClassReader(userBytes).accept(cn, 0);
        MethodNode clinit = null;
        for (MethodNode mn : cn.methods) {
            if ("<clinit>".equals(mn.name)) {
                clinit = mn;
                break;
            }
        }
        assertNotNull(clinit, "user class must have a <clinit> after anti-agent");
        AbstractInsnNode first = clinit.instructions.getFirst();
        assertNotNull(first);
        assertTrue(first instanceof MethodInsnNode, "first <clinit> insn must be a method call");
        MethodInsnNode call = (MethodInsnNode) first;
        assertEquals(Opcodes.INVOKESTATIC, call.getOpcode());
        assertEquals(guardInternal, call.owner);
        assertEquals("check", call.name);
        assertEquals("()V", call.desc);

        // (3) Class still loads and method still returns the right value.
        try (URLClassLoader cl = new URLClassLoader(
                new URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            Class<?> user = Class.forName("demo.User", true, cl);
            var m = user.getDeclaredMethod("answer");
            assertEquals(Integer.valueOf(42), m.invoke(null));
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
