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
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.renamerEnabled = false;
        b.stringEncryptionEnabled = false;
        b.flowEnabled = false;
        b.opaqueEnabled = false;
        b.numberEnabled = true;
        b.numberOnlyMagic = false;
        b.numberDepth = depth;
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
        b.localVarEnabled = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;
        new Obfuscator(b.build()).run();
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
