package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that per-class decoder names rotate: every class that gets a
 * blob-string or indy-call decoder injected receives a unique 8-character
 * suffix derived from its internal name, defeating grep-based recovery of
 * every decoder in the JAR.
 */
class NameRotationTest {

    @Test
    void decoderNamesRotatePerClass(@org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("multi.jar");
        writeJar(input);

        Path output = tmp.resolve("multi-obf.jar");

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.renameClasses = false;
        b.renameMethods = false;
        b.renameFields = false;
        b.stringEncryptionEnabled = true;
        b.stringStrength = ObfuscatorConfig.StringStrength.HEAVY;
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

        // Collect all synthetic $obf* method names from the output jar.
        Set<String> allObfMethodNames = new HashSet<>();
        Set<String> allObfFieldNames = new HashSet<>();
        int classesWithBlobDecoder = 0;
        int classesWithStringDecoder = 0;
        try (JarFile jf = new JarFile(output.toFile())) {
            var entries = jf.entries();
            while (entries.hasMoreElements()) {
                JarEntry e = entries.nextElement();
                if (!e.getName().endsWith(".class")) continue;
                byte[] bytes = jf.getInputStream(e).readAllBytes();
                ClassNode cn = new ClassNode();
                new ClassReader(new ByteArrayInputStream(bytes)).accept(cn, 0);
                boolean hasBlobDec = false, hasStrDec = false;
                for (MethodNode mn : cn.methods) {
                    if (mn.name.startsWith("$obf")) {
                        allObfMethodNames.add(mn.name);
                        if (mn.desc.equals("(I)Ljava/lang/String;")) hasBlobDec = true;
                        if (mn.desc.endsWith(")Ljava/lang/String;") && mn.desc.startsWith("(Ljava/lang/String;")) {
                            hasStrDec = true;
                        }
                    }
                }
                for (var fn : cn.fields) {
                    if (fn.name.startsWith("$obf")) allObfFieldNames.add(fn.name);
                }
                if (hasBlobDec) classesWithBlobDecoder++;
                if (hasStrDec) classesWithStringDecoder++;
            }
        }

        // Each class should get its own uniquely-named decoder.
        assertTrue(classesWithBlobDecoder >= 2, "Expected both classes to have a blob decoder");
        assertTrue(classesWithStringDecoder >= 2, "Expected both classes to have a string decoder");

        // No legacy hardcoded names.
        assertFalse(allObfMethodNames.contains("$obfBS"),
                "Legacy '$obfBS' decoder name must not appear after rotation");
        assertFalse(allObfMethodNames.contains("$obfD"),
                "Legacy '$obfD' decoder name must not appear after rotation");
        assertFalse(allObfMethodNames.contains("$obfDH"),
                "Legacy '$obfDH' decoder name must not appear after rotation");
        assertFalse(allObfFieldNames.contains("$obfBSb"),
                "Legacy '$obfBSb' blob field name must not appear after rotation");
        assertFalse(allObfFieldNames.contains("$obfBSo"),
                "Legacy '$obfBSo' offsets field name must not appear after rotation");
        assertFalse(allObfFieldNames.contains("$obfBSc"),
                "Legacy '$obfBSc' cache field name must not appear after rotation");

        // We should see at least 2 distinct blob-decoder method names and 2
        // distinct string-decoder method names across the 2 classes. Because
        // names are 9 chars (prefix + 8-char suffix), plain duplication is
        // highly unlikely for different class internal names.
        assertTrue(allObfMethodNames.size() >= 4,
                "Expected at least 4 distinct $obf* method names (2 classes x 2 decoder kinds); got: "
                        + allObfMethodNames);
    }

    private void writeJar(Path jarPath) throws Exception {
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jarPath), new Manifest())) {
            jos.putNextEntry(new JarEntry("A.class"));
            jos.write(buildClass("A", "alpha", "beta"));
            jos.closeEntry();
            jos.putNextEntry(new JarEntry("B.class"));
            jos.write(buildClass("B", "gamma", "delta"));
            jos.closeEntry();
        }
    }

    private byte[] buildClass(String name, String s1, String s2) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor m1 = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m1",
                "()Ljava/lang/String;", null, null);
        m1.visitLdcInsn(s1);
        m1.visitInsn(Opcodes.ARETURN);
        m1.visitMaxs(1, 0);
        m1.visitEnd();

        MethodVisitor m2 = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "m2",
                "()Ljava/lang/String;", null, null);
        m2.visitLdcInsn(s2);
        m2.visitInsn(Opcodes.ARETURN);
        m2.visitMaxs(1, 0);
        m2.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
