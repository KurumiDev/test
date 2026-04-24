package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test for the CFG-flattening transformer. Builds a class
 * with a branching method, obfuscates it with <b>only</b>
 * {@code cfg-flatten} enabled, and:
 * <ol>
 *   <li>Verifies the emitted method contains at least one
 *       {@code LOOKUPSWITCH} instruction (the dispatch loop).</li>
 *   <li>Reloads the obfuscated class and exercises the method through
 *       every branch, asserting the runtime answers remain identical
 *       to the unobfuscated version.</li>
 * </ol>
 */
class CfgFlattenTest {

    @Test
    void flattensBranchingMethodAndPreservesBehavior(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        byte[] source = buildBranching("demo/Calc");
        writeJar(input, Map.of("demo/Calc.class", source));

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
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
        b.cfgFlattenEnabled = true;
        b.verifyAfterEach = false;
        b.failOnVerifyError = false;

        new Obfuscator(b.build()).run();

        byte[] flat;
        try (JarFile jf = new JarFile(output.toFile())) {
            JarEntry je = jf.getJarEntry("demo/Calc.class");
            assertNotNull(je);
            flat = jf.getInputStream(je).readAllBytes();
        }

        ClassNode cn = new ClassNode();
        new ClassReader(flat).accept(cn, 0);
        MethodNode target = null;
        for (MethodNode mn : cn.methods) {
            if ("answer".equals(mn.name)) { target = mn; break; }
        }
        assertNotNull(target);

        boolean hasSwitch = false;
        for (AbstractInsnNode a : target.instructions.toArray()) {
            if (a instanceof LookupSwitchInsnNode) { hasSwitch = true; break; }
        }
        assertTrue(hasSwitch, "flattened method should contain a dispatch LOOKUPSWITCH");

        try (URLClassLoader cl = new URLClassLoader(
                new URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            Class<?> calc = Class.forName("demo.Calc", true, cl);
            var m = calc.getDeclaredMethod("answer", int.class);
            assertEquals(Integer.valueOf(111), m.invoke(null, 1));
            assertEquals(Integer.valueOf(222), m.invoke(null, 2));
            assertEquals(Integer.valueOf(333), m.invoke(null, 3));
            assertEquals(Integer.valueOf(-1),  m.invoke(null, 99));
        }
    }

    /**
     * Builds a class with exactly one branching method long enough to
     * clear CfgFlattenTransformer's MIN_INSNS / MIN_BLOCKS thresholds:
     *
     * <pre>
     *   public static int answer(int n) {
     *       if (n == 1) return 111;
     *       if (n == 2) return 222;
     *       if (n == 3) return 333;
     *       return -1;
     *   }
     * </pre>
     */
    private static byte[] buildBranching(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "answer", "(I)I", null, null);
        mv.visitCode();

        Label notOne = new Label();
        Label notTwo = new Label();
        Label notThree = new Label();

        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitJumpInsn(Opcodes.IF_ICMPNE, notOne);
        mv.visitIntInsn(Opcodes.BIPUSH, 111);
        mv.visitInsn(Opcodes.IRETURN);

        mv.visitLabel(notOne);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitJumpInsn(Opcodes.IF_ICMPNE, notTwo);
        mv.visitIntInsn(Opcodes.SIPUSH, 222);
        mv.visitInsn(Opcodes.IRETURN);

        mv.visitLabel(notTwo);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_3);
        mv.visitJumpInsn(Opcodes.IF_ICMPNE, notThree);
        mv.visitIntInsn(Opcodes.SIPUSH, 333);
        mv.visitInsn(Opcodes.IRETURN);

        mv.visitLabel(notThree);
        mv.visitInsn(Opcodes.ICONST_M1);
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
