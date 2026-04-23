package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Builds a tiny JAR in memory, obfuscates it, and verifies the resulting class
 * still loads and returns the expected value.
 */
class EndToEndTest {

    @Test
    void obfuscatesTinyJarAndStillRuns(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("hello.jar");
        writeHelloJar(input);

        Path output = tmp.resolve("hello-obf.jar");
        Path mapping = tmp.resolve("mapping.txt");

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        // keep class rename off so the classloader can find Hello.greet
        b.renameClasses = false;
        b.renameMethods = false;
        b.renameFields = false;
        b.stringEncryptionEnabled = true;
        b.flowEnabled = true;
        b.opaqueEnabled = true;
        b.numberEnabled = true;
        b.bogusExceptionEnabled = false;
        b.invokeDynamicEnabled = false;
        b.localVarEnabled = true;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.saveMapping = mapping;
        b.autoExempt = false;

        new Obfuscator(b.build()).run();

        assertTrue(Files.exists(output), "output JAR written");

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                EndToEndTest.class.getClassLoader())) {
            Class<?> hello = Class.forName("Hello", true, cl);
            Method greet = hello.getMethod("greet");
            String result = (String) greet.invoke(null);
            assertEquals("hello world", result);
        }
    }

    private void writeHelloJar(Path jarPath) throws Exception {
        byte[] classBytes = buildHelloClass();
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath), new Manifest())) {
            jos.putNextEntry(new JarEntry("Hello.class"));
            jos.write(classBytes);
            jos.closeEntry();
        }
    }

    private byte[] buildHelloClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "Hello", null, "java/lang/Object", null);

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor greet = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "greet",
                "()Ljava/lang/String;", null, null);
        greet.visitLdcInsn("hello ");
        greet.visitLdcInsn("world");
        greet.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat",
                "(Ljava/lang/String;)Ljava/lang/String;", false);
        // produce a number constant for the number-obfuscation pass
        greet.visitLdcInsn(9999);
        greet.visitInsn(Opcodes.POP);
        greet.visitInsn(Opcodes.ARETURN);
        greet.visitMaxs(2, 0);
        greet.visitEnd();

        cw.visitEnd();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] out = cw.toByteArray();
        baos.writeBytes(out);
        return out;
    }
}
