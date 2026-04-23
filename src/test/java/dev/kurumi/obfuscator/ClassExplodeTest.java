package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the {@link dev.kurumi.obfuscator.transformers.ClassExploderTransformer}
 * emits synthetic worker classes, wires them into the original class, and
 * produces a JAR that still verifies.
 */
class ClassExplodeTest {

    @Test
    void inflatesClassCountAndWiresWorkers(
            @org.junit.jupiter.api.io.TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        writeInputJar(input);

        Path output = tmp.resolve("out.jar");

        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = input;
        b.output = output;
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.renameClasses = false;
        b.renameMethods = false;
        b.renameFields = false;
        b.renameLocalVars = false;
        b.classExplodeEnabled = true;
        // Turn the rest off so the test is tight; exploder runs as a single
        // independent pass.
        b.stringEncryptionEnabled = false;
        b.flowEnabled = false;
        b.opaqueEnabled = false;
        b.junkCodeEnabled = false;
        b.numberEnabled = false;
        b.classLiteralEnabled = false;
        b.stringConcatEnabled = false;
        b.indyCallEnabled = false;
        b.blobStringEnabled = false;
        b.accessFlagsEnabled = false;
        b.memberShufflerEnabled = false;
        b.sourceScrubEnabled = false;
        b.localVarTableEnabled = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;

        new Obfuscator(b.build()).run();

        int classCount = 0;
        Set<String> workerClassNames = new HashSet<>();
        Set<String> callSitesToWorkers = new HashSet<>();

        try (JarFile jf = new JarFile(output.toFile())) {
            var en = jf.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (!e.getName().endsWith(".class")) continue;
                classCount++;
                ClassNode cn = readClass(jf, e);

                if (isWorkerName(cn.name)) {
                    workerClassNames.add(cn.name);
                }
            }

            // Second pass: scan call sites on the original class to
            // confirm cross-class wiring.
            var en2 = jf.entries();
            while (en2.hasMoreElements()) {
                JarEntry e = en2.nextElement();
                if (!e.getName().endsWith(".class")) continue;
                ClassNode cn = readClass(jf, e);
                if (isWorkerName(cn.name)) continue; // skip workers themselves
                for (MethodNode mn : cn.methods) {
                    if (mn.instructions == null) continue;
                    for (var it = mn.instructions.iterator(); it.hasNext(); ) {
                        var ins = it.next();
                        if (ins instanceof MethodInsnNode mi
                                && workerClassNames.contains(mi.owner)) {
                            callSitesToWorkers.add(cn.name + "." + mn.name
                                    + " -> " + mi.owner + "." + mi.name);
                        }
                    }
                }
            }
        }

        // We had 1 original; after explosion, expect the default 12 workers.
        assertTrue(classCount >= 12,
                "expected class count >= 13 after explosion, got " + classCount);
        assertTrue(workerClassNames.size() >= 10,
                "expected at least 10 worker classes, got " + workerClassNames);
        assertTrue(callSitesToWorkers.size() >= 1,
                "expected at least one call site from the original class into a worker, "
                        + "got " + callSitesToWorkers);
    }

    private static boolean isWorkerName(String internal) {
        int slash = internal.lastIndexOf('/');
        String simple = slash < 0 ? internal : internal.substring(slash + 1);
        int underscore = simple.indexOf('_');
        if (underscore <= 0) return false;
        String root = simple.substring(0, underscore);
        for (String r : dev.kurumi.obfuscator.transformers.ClassExploderTransformer
                .misleadingClassRoots()) {
            if (r.equals(root)) return true;
        }
        return false;
    }

    private static void writeInputJar(Path input) throws Exception {
        byte[] bytes = buildClass();
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(input), new Manifest())) {
            JarEntry je = new JarEntry("demo/Target.class");
            jos.putNextEntry(je);
            jos.write(bytes);
            jos.closeEntry();
        }
    }

    private static byte[] buildClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/Target", null, "java/lang/Object", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();
        MethodVisitor mv = cw.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "entry", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitLdcInsn(Integer.valueOf(17));
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static ClassNode readClass(JarFile jf, JarEntry e) throws Exception {
        try (var is = jf.getInputStream(e); ByteArrayOutputStream buf = new ByteArrayOutputStream()) {
            is.transferTo(buf);
            ClassReader cr = new ClassReader(buf.toByteArray());
            ClassNode cn = new ClassNode();
            cr.accept(cn, 0);
            return cn;
        }
    }
}
