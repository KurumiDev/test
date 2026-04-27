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
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies two adversarial-hardening properties introduced alongside
 * {@link dev.kurumi.obfuscator.transformers.JunkCodeInjector}:
 *
 * <ol>
 *   <li>Junk decoys are emitted with <b>misleading domain names</b>
 *       (e.g. {@code checkLicense_XXX}, {@code heartbeat_XXX}) rather
 *       than the neutral {@code $obfJk<hash>} scheme, exploiting the
 *       semantic priors of LLM-based reverse engineers.</li>
 *   <li>{@link dev.kurumi.obfuscator.transformers.OpaquePredicateTransformer}
 *       occasionally emits a predicate that <b>calls a honeypot method</b>
 *       from the same class, so the decoy appears load-bearing in the
 *       decompiler output (a visible cross-reference from a real
 *       entry-point method).</li>
 * </ol>
 */
class HoneypotDecoyTest {

    // Honeypot names are now generated per-JAR by combining a verb prefix
    // (from a fixed pool exposed by JunkCodeInjector#honeypotVerbs()) with
    // a CamelCase noun. So instead of matching a hard-coded list of full
    // names we match the structural pattern: <known-verb><CapitalLetter><word>_<hex>.
    private static final Pattern HONEYPOT_NAME = Pattern.compile(
            "^(?:check|verify|validate|fetch|report|audit|ping|rotate|decode|refresh|"
                    + "compute|resolve|load|ensure|guard|sign|encrypt|register)"
                    + "[A-Z][A-Za-z]+_[0-9a-f]+$");

    @Test
    void emitsAdversarialNamesAndWiresHoneypotsIntoPredicates(
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
        // Enable the minimum surface we need.
        b.junkCodeEnabled = true;
        b.opaqueEnabled = true;
        b.opaqueType = ObfuscatorConfig.OpaqueType.MIXED;
        // Keep the input pool stable so the JunkCodeInjector's
        // pool-fingerprint-derived RNG produces a deterministic
        // honeypot/decoy mix. Runtime-keyed number obfuscation
        // (v2.1.3+) injects a per-class String LDC into <clinit>
        // which would otherwise pull StringEncryptionTransformer's
        // probe class into the pool and shift the fingerprint.
        b.numberRuntimeKeyed = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        b.autoExempt = false;
        new Obfuscator(b.build()).run();

        // Walk every class in the obfuscated JAR and collect (a) any honeypot
        // method definitions, (b) any MethodInsnNode call sites that target
        // those honeypots from a non-honeypot method.
        Set<String> honeypots = new HashSet<>();
        Set<String> honeypotCallers = new HashSet<>();

        try (JarFile jf = new JarFile(output.toFile())) {
            var en = jf.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (!e.getName().endsWith(".class")) continue;
                ClassNode cn = readClass(jf, e);

                // Index honeypot defs on this class.
                Set<String> localHoneypots = new HashSet<>();
                for (MethodNode mn : cn.methods) {
                    if (HONEYPOT_NAME.matcher(mn.name).matches()) {
                        honeypots.add(cn.name + "." + mn.name);
                        localHoneypots.add(mn.name);
                    }
                }
                // Find call sites into those honeypots from non-honeypot
                // methods on the same class.
                for (MethodNode mn : cn.methods) {
                    if (localHoneypots.contains(mn.name)) continue;
                    if (mn.instructions == null) continue;
                    for (var it = mn.instructions.iterator(); it.hasNext(); ) {
                        var ins = it.next();
                        if (ins instanceof MethodInsnNode mi
                                && mi.owner.equals(cn.name)
                                && localHoneypots.contains(mi.name)) {
                            honeypotCallers.add(cn.name + "." + mn.name
                                    + " -> " + mi.name);
                        }
                    }
                }
            }
        }

        assertFalse(honeypots.isEmpty(),
                "Expected at least one honeypot decoy method in the obfuscated JAR");
        assertFalse(honeypotCallers.isEmpty(),
                "Expected at least one real method to call a honeypot decoy "
                        + "(opaque-predicate wiring). Honeypots present: " + honeypots);
    }

    // ------------------------------------------------------------------
    // Tiny input JAR containing a single class with a handful of methods.
    // Multiple methods raise the probability that at least one opaque
    // predicate picks the honeypot strategy (1 in 4 chance per method).
    // ------------------------------------------------------------------
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
        // <init>
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();
        // Several static methods so there are multiple opaque-predicate
        // insertion points.
        for (int i = 0; i < 15; i++) {
            MethodVisitor mv = cw.visitMethod(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "entry" + i, "(I)I", null, null);
            mv.visitCode();
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitLdcInsn(Integer.valueOf(17 + i));
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();
        }
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
