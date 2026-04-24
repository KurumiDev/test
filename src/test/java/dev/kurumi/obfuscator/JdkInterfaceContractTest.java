package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression test for the fortitude-plugin AbstractMethodError bug: when a
 * pool class implements a JDK interface we don't have a library node for
 * (e.g. java.lang.Runnable, java.util.concurrent.Callable), the renamer
 * must leave the interface method's name untouched. Otherwise virtual
 * dispatch from JDK code (Bukkit scheduler, ExecutorService, etc.) fails
 * at runtime with {@code AbstractMethodError: Receiver class X does not
 * define or inherit an implementation of the resolved method}.
 */
class JdkInterfaceContractTest {

    @Test
    void runnableRunIsPreserved(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("runnable.jar");
        writeJar(input, runnableTaskClass(), callableTaskClass());
        Path output = tmp.resolve("runnable-obf.jar");

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.renameClasses = false;
        b.renameMethods = true;
        b.renameFields = true;
        b.renamerEnabled = true;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;

        new Obfuscator(b.build()).run();

        assertTrue(Files.exists(output));

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                JdkInterfaceContractTest.class.getClassLoader())) {
            // Runnable: invoke via the Runnable contract, not via reflection
            // on the impl class directly. If run() was renamed to "w" the
            // JVM raises AbstractMethodError here.
            Class<?> runnableCls = Class.forName("pkg.RunnableTask", true, cl);
            AtomicInteger counter = new AtomicInteger();
            Object instance = runnableCls.getConstructor(AtomicInteger.class).newInstance(counter);
            Runnable r = (Runnable) instance;
            r.run();
            // Counter was externally visible before, observed after r.run()
            // via the same reference. If run() was silently renamed to "w",
            // the JVM raises AbstractMethodError on the r.run() call above.
            assertEquals(1, counter.get(), "run() must increment the injected counter");

            // Callable: same test but for parametric-interface dispatch.
            Class<?> callableCls = Class.forName("pkg.CallableTask", true, cl);
            @SuppressWarnings("unchecked")
            Callable<String> c = (Callable<String>) callableCls.getDeclaredConstructor().newInstance();
            assertEquals("CALLED", c.call());
        }
    }

    private void writeJar(Path jar, byte[]... classes) throws Exception {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar), new Manifest())) {
            for (byte[] cls : classes) {
                String name = classNameOf(cls);
                jos.putNextEntry(new JarEntry(name + ".class"));
                jos.write(cls);
                jos.closeEntry();
            }
        }
    }

    private static String classNameOf(byte[] bytes) {
        org.objectweb.asm.ClassReader cr = new org.objectweb.asm.ClassReader(bytes);
        return cr.getClassName();
    }

    private byte[] runnableTaskClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "pkg/RunnableTask",
                null, "java/lang/Object", new String[]{"java/lang/Runnable"});

        FieldVisitor fv = cw.visitField(Opcodes.ACC_PUBLIC, "counter",
                "Ljava/util/concurrent/atomic/AtomicInteger;", null, null);
        fv.visitEnd();

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>",
                "(Ljava/util/concurrent/atomic/AtomicInteger;)V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitVarInsn(Opcodes.ALOAD, 1);
        init.visitFieldInsn(Opcodes.PUTFIELD, "pkg/RunnableTask", "counter",
                "Ljava/util/concurrent/atomic/AtomicInteger;");
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        MethodVisitor run = cw.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.visitVarInsn(Opcodes.ALOAD, 0);
        run.visitFieldInsn(Opcodes.GETFIELD, "pkg/RunnableTask", "counter",
                "Ljava/util/concurrent/atomic/AtomicInteger;");
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                "java/util/concurrent/atomic/AtomicInteger", "incrementAndGet", "()I", false);
        run.visitInsn(Opcodes.POP);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private byte[] callableTaskClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "pkg/CallableTask",
                "Ljava/lang/Object;Ljava/util/concurrent/Callable<Ljava/lang/String;>;",
                "java/lang/Object", new String[]{"java/util/concurrent/Callable"});

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        // Callable.call() -> Object — bridge over String-returning impl
        MethodVisitor call = cw.visitMethod(Opcodes.ACC_PUBLIC, "call",
                "()Ljava/lang/Object;", null, new String[]{"java/lang/Exception"});
        call.visitLdcInsn("CALLED");
        call.visitInsn(Opcodes.ARETURN);
        call.visitMaxs(0, 0);
        call.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
