package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for {@code number-obfuscation}: every randomly chosen XOR /
 * SUB style must reliably produce the original value.
 *
 * <p>Hits a tight loop of method calls with int/long literals at multiple
 * depths so all four switch styles (and any depth-N nested combinations)
 * fire many times. Probability of a single buggy style escaping = (3/4)^N.
 */
class NumberObfuscationCorrectnessTest {

    private static final int CALLS = 200;

    @Test
    void intIdentitiesAreCorrectAcrossAllStylesAndDepths(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        for (int depth = 1; depth <= 4; depth++) {
            runIntCheck(tmp.resolve("int-d" + depth + ".jar"),
                    tmp.resolve("int-d" + depth + "-obf.jar"), depth);
        }
    }

    /**
     * When runtime-keyed mode is on (the default in v2.1.3+), every
     * obfuscated class must carry exactly one synthetic
     * {@code $<prefix>numKey_<hex>} {@code int} field, and the class
     * must still load and produce the same answer.
     *
     * <p>Without this layer, the XOR / SUB chains emitted by
     * {@link dev.kurumi.obfuscator.transformers.NumberObfuscationTransformer}
     * are pure-constant arithmetic and any decompiler with a constant-folding
     * pass collapses them back to the original literal. The runtime key is
     * the per-class hashCode of the class's own name XOR'd with a per-build
     * salt, computed in {@code <clinit>} from a {@code String.hashCode()}
     * call &mdash; an expression decompilers preserve verbatim.
     */
    @Test
    void runtimeKeyedModeAddsPerClassKeyField(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("rk-in.jar");
        Path output = tmp.resolve("rk-out.jar");
        writeJar(input, "IntCarrier", buildIntCarrier());

        ObfuscatorConfig.Builder b = baselineNumberOnly();
        b.input = input;
        b.output = output;
        b.numberDepth = 1;
        b.numberRuntimeKeyed = true;
        new Obfuscator(b.build()).run();

        // Locate the synthetic numKey field on IntCarrier.
        boolean foundField = false;
        try (JarFile jf = new JarFile(output.toFile())) {
            JarEntry je = jf.getJarEntry("IntCarrier.class");
            byte[] bytes = jf.getInputStream(je).readAllBytes();
            ClassNode cn = new ClassNode();
            new ClassReader(bytes).accept(cn, 0);
            if (cn.fields != null) {
                for (FieldNode fn : cn.fields) {
                    if (fn.name.contains("numKey_") && fn.desc.equals("I")) {
                        foundField = true;
                        // The field must be private static final synthetic so
                        // it survives renaming and isn't accidentally read by
                        // user code.
                        assertTrue((fn.access & Opcodes.ACC_PRIVATE) != 0,
                                "numKey field must be private");
                        assertTrue((fn.access & Opcodes.ACC_STATIC) != 0,
                                "numKey field must be static");
                        assertTrue((fn.access & Opcodes.ACC_FINAL) != 0,
                                "numKey field must be final");
                    }
                }
            }
        }
        assertTrue(foundField, "expected a $<prefix>numKey_<hex> field on IntCarrier");

        // And the class must still produce the right answer at runtime.
        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                NumberObfuscationCorrectnessTest.class.getClassLoader())) {
            Class<?> c = Class.forName("IntCarrier", true, cl);
            Method m = c.getMethod("sum");
            int got = (int) m.invoke(null);
            int expected = (-889275714 + 42 + 0 + 1 + (-1) + 65535 + Integer.MIN_VALUE + Integer.MAX_VALUE) * CALLS;
            assertEquals(expected, got, "runtime-keyed int identities");
        }
    }

    @Test
    void longIdentitiesAreCorrectAcrossAllStylesAndDepths(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        for (int depth = 1; depth <= 4; depth++) {
            runLongCheck(tmp.resolve("long-d" + depth + ".jar"),
                    tmp.resolve("long-d" + depth + "-obf.jar"), depth);
        }
    }

    private void runIntCheck(Path input, Path output, int depth) throws Exception {
        writeJar(input, "IntCarrier", buildIntCarrier());
        runNumberOnly(input, output, depth);

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                NumberObfuscationCorrectnessTest.class.getClassLoader())) {
            Class<?> c = Class.forName("IntCarrier", true, cl);
            Method m = c.getMethod("sum");
            int got = (int) m.invoke(null);
            // Sum of CONSTANTS repeated CALLS times; see buildIntCarrier()
            int expected = (-889275714 + 42 + 0 + 1 + (-1) + 65535 + Integer.MIN_VALUE + Integer.MAX_VALUE) * CALLS;
            assertEquals(expected, got, "depth=" + depth + " int identities");
        }
    }

    private void runLongCheck(Path input, Path output, int depth) throws Exception {
        writeJar(input, "LongCarrier", buildLongCarrier());
        runNumberOnly(input, output, depth);

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                NumberObfuscationCorrectnessTest.class.getClassLoader())) {
            Class<?> c = Class.forName("LongCarrier", true, cl);
            Method m = c.getMethod("sum");
            long got = (long) m.invoke(null);
            long expected = (-889275714L + 42L + 0L + 1L + (-1L) + 0xCAFEBABE_DEADBEEFL + Long.MIN_VALUE + Long.MAX_VALUE) * (long) CALLS;
            assertEquals(expected, got, "depth=" + depth + " long identities");
        }
    }

    private void runNumberOnly(Path input, Path output, int depth) throws Exception {
        ObfuscatorConfig.Builder b = baselineNumberOnly();
        b.input = input;
        b.output = output;
        b.numberDepth = depth;
        // Pre-runtime-keying tests assert the algebraic identity of the
        // generated chain &mdash; {@code value = chain(value)} &mdash;
        // independent of any per-class field. Disable runtime keying so
        // we test the chain itself rather than the keying envelope.
        b.numberRuntimeKeyed = false;
        new Obfuscator(b.build()).run();
    }

    private static ObfuscatorConfig.Builder baselineNumberOnly() {
        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.renamerEnabled = false;
        b.stringEncryptionEnabled = false;
        b.flowEnabled = false;
        b.opaqueEnabled = false;
        b.numberEnabled = true;
        b.numberOnlyMagic = false;
        b.bogusExceptionEnabled = false;
        b.invokeDynamicEnabled = false;
        b.classLiteralEnabled = false;
        b.stringConcatEnabled = false;
        b.indyCallEnabled = false;
        b.indyFieldEnabled = false;
        b.junkCodeEnabled = false;
        b.accessFlagsEnabled = false;
        b.memberShufflerEnabled = false;
        b.sourceScrubEnabled = false;
        b.blobStringEnabled = false;
        b.localVarTableEnabled = false;
        b.classExplodeEnabled = false;
        b.encryptedClassVaultEnabled = false;
        b.cfgFlattenEnabled = false;
        b.fakeAnnotationsEnabled = false;
        b.antiAgentEnabled = false;
        b.watermarkEnabled = false;
        b.antiTamperEnabled = false;
        b.antiRecafEnabled = false;
        b.localVarEnabled = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;
        return b;
    }

    private byte[] buildIntCarrier() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "IntCarrier", null, "java/lang/Object", null);
        emitDefaultCtor(cw);

        MethodVisitor sum = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sum", "()I", null, null);
        sum.visitCode();
        // accumulator
        sum.visitInsn(Opcodes.ICONST_0);
        sum.visitVarInsn(Opcodes.ISTORE, 0);
        // for (i = 0; i < CALLS; i++) acc += sum_of_consts;
        sum.visitInsn(Opcodes.ICONST_0);
        sum.visitVarInsn(Opcodes.ISTORE, 1);
        org.objectweb.asm.Label loopHead = new org.objectweb.asm.Label();
        org.objectweb.asm.Label loopExit = new org.objectweb.asm.Label();
        sum.visitLabel(loopHead);
        sum.visitVarInsn(Opcodes.ILOAD, 1);
        sum.visitLdcInsn(CALLS);
        sum.visitJumpInsn(Opcodes.IF_ICMPGE, loopExit);
        // acc += each constant
        int[] consts = {-889275714, 42, 0, 1, -1, 65535, Integer.MIN_VALUE, Integer.MAX_VALUE};
        for (int v : consts) {
            sum.visitVarInsn(Opcodes.ILOAD, 0);
            sum.visitLdcInsn(v);
            sum.visitInsn(Opcodes.IADD);
            sum.visitVarInsn(Opcodes.ISTORE, 0);
        }
        sum.visitIincInsn(1, 1);
        sum.visitJumpInsn(Opcodes.GOTO, loopHead);
        sum.visitLabel(loopExit);
        sum.visitVarInsn(Opcodes.ILOAD, 0);
        sum.visitInsn(Opcodes.IRETURN);
        sum.visitMaxs(0, 0);
        sum.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private byte[] buildLongCarrier() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "LongCarrier", null, "java/lang/Object", null);
        emitDefaultCtor(cw);

        MethodVisitor sum = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sum", "()J", null, null);
        sum.visitCode();
        // long acc = 0;
        sum.visitInsn(Opcodes.LCONST_0);
        sum.visitVarInsn(Opcodes.LSTORE, 0);
        // int i = 0;
        sum.visitInsn(Opcodes.ICONST_0);
        sum.visitVarInsn(Opcodes.ISTORE, 2);
        org.objectweb.asm.Label loopHead = new org.objectweb.asm.Label();
        org.objectweb.asm.Label loopExit = new org.objectweb.asm.Label();
        sum.visitLabel(loopHead);
        sum.visitVarInsn(Opcodes.ILOAD, 2);
        sum.visitLdcInsn(CALLS);
        sum.visitJumpInsn(Opcodes.IF_ICMPGE, loopExit);
        long[] consts = {-889275714L, 42L, 0L, 1L, -1L, 0xCAFEBABE_DEADBEEFL, Long.MIN_VALUE, Long.MAX_VALUE};
        for (long v : consts) {
            sum.visitVarInsn(Opcodes.LLOAD, 0);
            sum.visitLdcInsn(v);
            sum.visitInsn(Opcodes.LADD);
            sum.visitVarInsn(Opcodes.LSTORE, 0);
        }
        sum.visitIincInsn(2, 1);
        sum.visitJumpInsn(Opcodes.GOTO, loopHead);
        sum.visitLabel(loopExit);
        sum.visitVarInsn(Opcodes.LLOAD, 0);
        sum.visitInsn(Opcodes.LRETURN);
        sum.visitMaxs(0, 0);
        sum.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void emitDefaultCtor(ClassWriter cw) {
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
    }

    private static void writeJar(Path jarPath, String className, byte[] classBytes) throws Exception {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath), new Manifest())) {
            jos.putNextEntry(new JarEntry(className + ".class"));
            jos.write(classBytes);
            jos.closeEntry();
        }
    }
}
