package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test for
 * {@link dev.kurumi.obfuscator.transformers.IndyFieldTransformer}.
 *
 * <p>Builds a two-class JAR where class {@code A} reads a static int field
 * on {@code B} and writes/reads an instance field on {@code B}. After
 * obfuscation with indy-field enabled, none of the four
 * {@code GETFIELD/PUTFIELD/GETSTATIC/PUTSTATIC} opcodes should remain for
 * those pool-owned field accesses &mdash; they must all be
 * {@code INVOKEDYNAMIC} instructions instead. The JAR is then loaded in a
 * fresh classloader and {@code A.entry()} is invoked to confirm the full
 * runtime round-trip works (BSM decrypts names, resolves via
 * {@code privateLookupIn}, adapts to call-site type, returns correct
 * result).
 */
class IndyFieldEndToEndTest {

    @Test
    void indyFieldSurvivesObfuscation(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("indy-field.jar");
        writeJar(input);

        Path output = tmp.resolve("indy-field-obf.jar");

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
        b.indyCallEnabled = false;
        b.indyFieldEnabled = true;
        b.junkCodeEnabled = false;
        b.accessFlagsEnabled = false;
        b.memberShufflerEnabled = false;
        b.sourceScrubEnabled = false;
        b.localVarEnabled = true;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;

        new Obfuscator(b.build()).run();

        // Byte-level check: no direct GETFIELD/PUTFIELD/GETSTATIC/PUTSTATIC
        // for A.entry() on B's fields should survive — they are all now
        // INVOKEDYNAMIC.
        assertAllFieldAccessesRewritten(output);

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                IndyFieldEndToEndTest.class.getClassLoader())) {
            Class<?> a = Class.forName("A", true, cl);
            Method entry = a.getMethod("entry");
            Object result = entry.invoke(null);
            // Expected: Read static counter (=10), compute + put as instance field,
            // read instance field back, returns 10 + 32 = 42.
            assertEquals(42, result);
        }
    }

    private static void assertAllFieldAccessesRewritten(Path jar) throws Exception {
        int indyCount = 0;
        try (JarFile jf = new JarFile(jar.toFile())) {
            var entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry je = entries.nextElement();
                if (!je.getName().equals("A.class")) continue;
                try (var is = jf.getInputStream(je)) {
                    ClassReader cr = new ClassReader(is);
                    ClassNode cn = new ClassNode();
                    cr.accept(cn, 0);
                    for (MethodNode mn : cn.methods) {
                        if (!"entry".equals(mn.name)) continue;
                        for (AbstractInsnNode ins : mn.instructions.toArray()) {
                            if (ins instanceof FieldInsnNode fin
                                    && ("B".equals(fin.owner) || "A".equals(fin.owner))) {
                                int op = fin.getOpcode();
                                assertFalse(
                                        op == Opcodes.GETFIELD || op == Opcodes.PUTFIELD
                                                || op == Opcodes.GETSTATIC || op == Opcodes.PUTSTATIC,
                                        "Direct field access left after indy-field: "
                                                + fin.owner + "." + fin.name);
                            }
                            if (ins instanceof InvokeDynamicInsnNode) indyCount++;
                        }
                    }
                }
            }
        }
        assertTrue(indyCount >= 3,
                "Expected at least 3 indy field-access sites in A.entry(), got " + indyCount);
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

    /**
     * <pre>
     * public class A {
     *   public static int entry() {
     *     int c = B.COUNTER;       // GETSTATIC B.COUNTER:I  -> indy getter
     *     B b = new B();
     *     b.value = 32;            // PUTFIELD  B.value:I    -> indy setter
     *     return c + b.value;      // GETFIELD  B.value:I    -> indy getter
     *   }
     * }
     * </pre>
     */
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
        // int c = B.COUNTER
        mv.visitFieldInsn(Opcodes.GETSTATIC, "B", "COUNTER", "I");
        mv.visitVarInsn(Opcodes.ISTORE, 0);
        // B b = new B();
        mv.visitTypeInsn(Opcodes.NEW, "B");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "B", "<init>", "()V", false);
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        // b.value = 32
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitIntInsn(Opcodes.BIPUSH, 32);
        mv.visitFieldInsn(Opcodes.PUTFIELD, "B", "value", "I");
        // return c + b.value
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitFieldInsn(Opcodes.GETFIELD, "B", "value", "I");
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * <pre>
     * public class B {
     *   public static int COUNTER = 10;
     *   public int value;
     * }
     * </pre>
     */
    private byte[] buildB() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "B", null, "java/lang/Object", null);
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "COUNTER", "I", null, null)
                .visitEnd();
        cw.visitField(Opcodes.ACC_PUBLIC, "value", "I", null, null).visitEnd();

        MethodVisitor clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitIntInsn(Opcodes.BIPUSH, 10);
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "B", "COUNTER", "I");
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(1, 0);
        clinit.visitEnd();

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
