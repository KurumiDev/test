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
 * End-to-end test for {@link dev.kurumi.obfuscator.transformers.IndyCallTransformer}.
 *
 * <p>Builds a two-class JAR where class {@code A} has a static method that
 * calls a virtual method on class {@code B}. Runs the obfuscator with
 * indy-call enabled so both call sites get wrapped in {@code invokedynamic}
 * backed by our per-class bootstrap. Loads the result in a fresh classloader
 * and invokes {@code A.entry()}, verifying the whole round-trip works at the
 * JVM link step — i.e. our bootstrap correctly resolves the target, the
 * decoder decrypts the names, and the resulting {@link java.lang.invoke.MethodHandle}
 * is linkable against the call-site type.
 */
class IndyCallEndToEndTest {

    @Test
    void indyCallSurvivesObfuscation(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("indy.jar");
        writeJar(input);

        Path output = tmp.resolve("indy-obf.jar");

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
        b.indyCallEnabled = true;
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
                IndyCallEndToEndTest.class.getClassLoader())) {
            Class<?> a = Class.forName("A", true, cl);
            Method entry = a.getMethod("entry");
            Object result = entry.invoke(null);
            assertEquals(42, result);
        }
    }

    private void writeJar(Path jarPath) throws Exception {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath), new Manifest())) {
            jos.putNextEntry(new JarEntry("A.class"));
            jos.write(buildA());
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("B.class"));
            jos.write(buildB());
            jos.closeEntry();
        }
    }

    // public class A {
    //   public static int entry() { return new B().compute(7); }
    // }
    private byte[] buildA() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "A", null, "java/lang/Object", null);

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "entry",
                "()I", null, null);
        mv.visitTypeInsn(Opcodes.NEW, "B");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "B", "<init>", "()V", false);
        mv.visitIntInsn(Opcodes.BIPUSH, 7);
        // INVOKEVIRTUAL B.compute(I)I  — this is what indy-call rewrites
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "B", "compute", "(I)I", false);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(3, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    // public class B {
    //   public int compute(int x) { return helper(x) * 6; }
    //   public static int helper(int x) { return x; }   // INVOKESTATIC
    // }
    private byte[] buildB() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "B", null, "java/lang/Object", null);

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor compute = cw.visitMethod(Opcodes.ACC_PUBLIC, "compute", "(I)I", null, null);
        compute.visitVarInsn(Opcodes.ILOAD, 1);
        compute.visitMethodInsn(Opcodes.INVOKESTATIC, "B", "helper", "(I)I", false);
        compute.visitIntInsn(Opcodes.BIPUSH, 6);
        compute.visitInsn(Opcodes.IMUL);
        compute.visitInsn(Opcodes.IRETURN);
        compute.visitMaxs(2, 2);
        compute.visitEnd();

        MethodVisitor helper = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "helper",
                "(I)I", null, null);
        helper.visitVarInsn(Opcodes.ILOAD, 0);
        helper.visitInsn(Opcodes.IRETURN);
        helper.visitMaxs(1, 1);
        helper.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
