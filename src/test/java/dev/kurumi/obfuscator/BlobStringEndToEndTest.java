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
 * End-to-end test for {@link dev.kurumi.obfuscator.transformers.BlobStringTransformer}.
 *
 * <p>Builds a trivial class containing three distinct LDC string constants,
 * runs the obfuscator with only blob-string enabled, loads the result, and
 * verifies each call site still returns the correct string. This exercises
 * the full decoder path: {@code <clinit>} blob decryption, offsets table
 * population, cache array allocation, and the lazy-fetch decoder method.
 */
class BlobStringEndToEndTest {

    @Test
    void blobStringSurvivesObfuscation(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("blob.jar");
        writeJar(input);

        Path output = tmp.resolve("blob-obf.jar");

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
        b.blobStringEnabled = true;
        b.junkCodeEnabled = false;
        b.accessFlagsEnabled = false;
        b.memberShufflerEnabled = false;
        b.sourceScrubEnabled = false;
        b.localVarEnabled = true;
        b.localVarTableEnabled = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;

        new Obfuscator(b.build()).run();

        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                BlobStringEndToEndTest.class.getClassLoader())) {
            Class<?> owner = Class.forName("Owner", true, cl);
            Method first = owner.getMethod("first");
            Method second = owner.getMethod("second");
            Method concat = owner.getMethod("concat");
            assertEquals("hello", first.invoke(null));
            assertEquals("world", second.invoke(null));
            assertEquals("hellowhy", concat.invoke(null));
        }
    }

    private void writeJar(Path jarPath) throws Exception {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath), new Manifest())) {
            jos.putNextEntry(new JarEntry("Owner.class"));
            jos.write(buildOwner());
            jos.closeEntry();
        }
    }

    // public class Owner {
    //   public static String first()  { return "hello"; }
    //   public static String second() { return "world"; }
    //   public static String concat() { return "hello" + "why"; }   // two LDCs,
    //                                                                // "hello" shared
    // }
    private byte[] buildOwner() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "Owner", null, "java/lang/Object", null);

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        emitConstMethod(cw, "first", "hello");
        emitConstMethod(cw, "second", "world");

        MethodVisitor c = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "concat",
                "()Ljava/lang/String;", null, null);
        c.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
        c.visitInsn(Opcodes.DUP);
        c.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
        c.visitLdcInsn("hello");
        c.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        c.visitLdcInsn("why");
        c.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        c.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                "()Ljava/lang/String;", false);
        c.visitInsn(Opcodes.ARETURN);
        c.visitMaxs(2, 0);
        c.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private void emitConstMethod(ClassWriter cw, String name, String value) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name,
                "()Ljava/lang/String;", null, null);
        mv.visitLdcInsn(value);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
    }
}
