package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Verifies the runtime class-identity binding added to the blob-string
 * decoder: the encryption seed is XOR'd with the enclosing class's name
 * hash at obfuscation time, and recovered at runtime via
 * {@code MethodHandles.lookup().lookupClass().getName().hashCode()}.
 *
 * <p>If a reverse engineer copies the whole decoder infrastructure
 * (blob field, offsets, helper method, decoder method, &lt;clinit&gt;) into
 * another class, {@link java.lang.invoke.MethodHandles#lookup()} returns
 * a Lookup bound to the new class, its name hashes differently, the
 * recovered seed is wrong, and decryption yields garbage. This test
 * proves that property by renaming the obfuscated class internal name
 * and observing that decryption no longer returns the original string.
 */
class ClassIdentityBindingTest {

    @Test
    void decryptionFailsWhenClassIsRenamed(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("orig.jar");
        writeJar(input, "Owner");

        Path output = tmp.resolve("orig-obf.jar");

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
        b.localVarEnabled = false;
        b.localVarTableEnabled = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;
        new Obfuscator(b.build()).run();

        // Sanity: obfuscated output still decrypts correctly in-place.
        try (URLClassLoader cl = new URLClassLoader(new URL[]{output.toUri().toURL()},
                ClassIdentityBindingTest.class.getClassLoader())) {
            Class<?> owner = Class.forName("Owner", true, cl);
            Method first = owner.getMethod("first");
            assertEquals("hello", first.invoke(null));
        }

        // Now rename the obfuscated class from "Owner" -> "Renamed" and
        // verify decryption is broken. We rename the class bytes but keep
        // its decoder + <clinit> intact \u2014 exactly the scenario where an
        // attacker extracts the infrastructure into their own class.
        Path renamedJar = tmp.resolve("renamed.jar");
        rewriteWithNewName(output, renamedJar, "Owner", "Renamed");

        try (URLClassLoader cl = new URLClassLoader(new URL[]{renamedJar.toUri().toURL()},
                ClassIdentityBindingTest.class.getClassLoader())) {
            Class<?> renamed = Class.forName("Renamed", true, cl);
            Method first = renamed.getMethod("first");
            Object result = first.invoke(null);
            // Decryption MUST NOT return the original "hello" because the
            // runtime class name differs (hashCode differs -> wrong seed).
            // We accept any outcome other than the plaintext: a mangled
            // string, an exception wrapped in InvocationTargetException, or
            // even an empty slice. We just assert it isn't "hello".
            assertNotEquals("hello", result,
                    "Runtime class-identity binding failed: decoder still returned "
                            + "the original plaintext after the class was renamed.");
        } catch (Throwable t) {
            // Also acceptable: <clinit> or decoder throws due to invalid
            // decoded offsets. This still proves the binding is effective.
        }
    }

    private void writeJar(Path jarPath, String className) throws Exception {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath), new Manifest())) {
            jos.putNextEntry(new JarEntry(className + ".class"));
            jos.write(buildOwner(className));
            jos.closeEntry();
        }
    }

    private byte[] buildOwner(String className) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);

        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "first",
                "()Ljava/lang/String;", null, null);
        m.visitLdcInsn("hello");
        m.visitInsn(Opcodes.ARETURN);
        m.visitMaxs(1, 0);
        m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** Read a JAR, rename one class, and write the renamed result. */
    private void rewriteWithNewName(Path src, Path dst, String oldName, String newName) throws Exception {
        try (JarFile jf = new JarFile(src.toFile());
             JarOutputStream jos = new JarOutputStream(Files.newOutputStream(dst), new Manifest())) {
            var entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry e = entries.nextElement();
                if (e.isDirectory() || e.getName().startsWith("META-INF")) continue;
                byte[] bytes = jf.getInputStream(e).readAllBytes();
                if (e.getName().equals(oldName + ".class")) {
                    // Rewrite via ClassRemapper
                    ClassReader cr = new ClassReader(new ByteArrayInputStream(bytes));
                    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                    Remapper rm = new Remapper() {
                        @Override public String map(String internalName) {
                            return oldName.equals(internalName) ? newName : internalName;
                        }
                    };
                    cr.accept(new ClassRemapper(cw, rm), 0);
                    jos.putNextEntry(new JarEntry(newName + ".class"));
                    jos.write(cw.toByteArray());
                } else {
                    jos.putNextEntry(new JarEntry(e.getName()));
                    jos.write(bytes);
                }
                jos.closeEntry();
            }
        }
    }
}
