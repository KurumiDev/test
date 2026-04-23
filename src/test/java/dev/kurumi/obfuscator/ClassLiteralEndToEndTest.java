package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

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
 * Builds a JAR whose single method returns {@code String.class.getName()}
 * (a literal {@code .class} reference) and verifies the obfuscator rewrites
 * it to a {@code Class.forName}-based lookup that still resolves at runtime.
 */
class ClassLiteralEndToEndTest {

    @Test
    void classLiteralSurvivesObfuscation(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("cl.jar");
        writeJar(input);

        Path output = tmp.resolve("cl-obf.jar");

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.renameClasses = false;
        b.renameMethods = false;
        b.renameFields = false;
        b.classLiteralEnabled = true;
        b.stringEncryptionEnabled = true;
        b.stringStrength = ObfuscatorConfig.StringStrength.HEAVY;
        b.opaqueEnabled = true;
        b.flowEnabled = true;
        b.numberEnabled = true;
        b.bogusExceptionEnabled = false;
        b.invokeDynamicEnabled = false;
        b.localVarEnabled = true;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;

        new Obfuscator(b.build()).run();

        assertTrue(Files.exists(output));

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                ClassLiteralEndToEndTest.class.getClassLoader())) {
            Class<?> owner = Class.forName("Owner", true, cl);
            Method m = owner.getMethod("className");
            Object result = m.invoke(null);
            assertEquals("java.lang.String", result);
        }
    }

    private void writeJar(Path jarPath) throws Exception {
        byte[] classBytes = buildClass();
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath), new Manifest())) {
            jos.putNextEntry(new JarEntry("Owner.class"));
            jos.write(classBytes);
            jos.closeEntry();
        }
    }

    private byte[] buildClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "Owner", null, "java/lang/Object", null);

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "className",
                "()Ljava/lang/String;", null, null);
        // push String.class via LDC of a Type constant
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getName",
                "()Ljava/lang/String;", false);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
