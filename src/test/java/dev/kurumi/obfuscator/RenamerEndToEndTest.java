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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Multi-class JAR with virtual dispatch. Verifies the renamer preserves
 * inheritance semantics across classes while letting string encryption and
 * flow obfuscation run.
 */
class RenamerEndToEndTest {

    @Test
    void multiClassJarRoundTrips(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("multi.jar");
        writeJar(input);

        Path output = tmp.resolve("multi-obf.jar");

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.renameClasses = false; // keep class names so the test harness can load "pkg/Entry"
        b.renameMethods = true;
        b.renameFields = true;
        b.renamerEnabled = true;
        b.stringEncryptionEnabled = true;
        b.flowEnabled = true;
        b.opaqueEnabled = true;
        b.numberEnabled = true;
        b.bogusExceptionEnabled = true;
        b.invokeDynamicEnabled = false;
        b.localVarEnabled = true;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;
        // Do not rename Entry.entry() because reflection calls it by name
        b.exemptions = java.util.List.of("pkg.Entry#entry");

        new Obfuscator(b.build()).run();

        assertTrue(Files.exists(output));

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                RenamerEndToEndTest.class.getClassLoader())) {
            Class<?> entry = Class.forName("pkg.Entry", true, cl);
            Method run = entry.getMethod("entry");
            Object result = run.invoke(null);
            assertEquals("CHILD", result);
        }
    }

    private void writeJar(Path jar) throws Exception {
        byte[] parent = parentClass();
        byte[] child = childClass();
        byte[] entry = entryClass();
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar), new Manifest())) {
            jos.putNextEntry(new JarEntry("pkg/Parent.class"));
            jos.write(parent);
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("pkg/Child.class"));
            jos.write(child);
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("pkg/Entry.class"));
            jos.write(entry);
            jos.closeEntry();
        }
    }

    private byte[] parentClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "pkg/Parent", null, "java/lang/Object", null);
        writeSimpleInit(cw, "pkg/Parent");
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "label", "()Ljava/lang/String;", null, null);
        m.visitLdcInsn("PARENT");
        m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(1, 1);
        m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private byte[] childClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "pkg/Child", null, "pkg/Parent", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "pkg/Parent", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC, "label", "()Ljava/lang/String;", null, null);
        m.visitLdcInsn("CHILD");
        m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(1, 1);
        m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private byte[] entryClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "pkg/Entry", null, "java/lang/Object", null);
        writeSimpleInit(cw, "pkg/Entry");
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "entry",
                "()Ljava/lang/String;", null, null);
        m.visitTypeInsn(Opcodes.NEW, "pkg/Child");
        m.visitInsn(Opcodes.DUP);
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "pkg/Child", "<init>", "()V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "pkg/Parent", "label",
                "()Ljava/lang/String;", false);
        m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(2, 0);
        m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private void writeSimpleInit(ClassWriter cw, String owner) {
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
    }
}
