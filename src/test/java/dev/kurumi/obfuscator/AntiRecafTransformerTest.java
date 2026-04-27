package dev.kurumi.obfuscator;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests {@link
 * dev.kurumi.obfuscator.transformers.AntiRecafTransformer}.
 *
 * <p>Asserts that an obfuscated class:
 * <ul>
 *   <li>carries a non-empty bogus {@code Signature} attribute that
 *       declares a generic type parameter bounded by a phantom
 *       class ({@code &lt;T:L...Phantom;&gt;Ljava/lang/Object;});</li>
 *   <li>carries at least one class-level unknown attribute whose
 *       name ends in {@code "Trap"};</li>
 *   <li>carries at least one method-level unknown attribute on
 *       some non-{@code &lt;init&gt;} / non-{@code &lt;clinit&gt;}
 *       method whose name ends in {@code "TrapM"};</li>
 *   <li>still has runtime-identical behaviour: the class can be
 *       loaded and {@code greet()} returns the original
 *       plaintext.</li>
 * </ul>
 *
 * <p>The unknown-attribute checks use a custom {@link Attribute}
 * subclass passed to {@link ClassReader#accept} so ASM does not
 * silently drop the trap blobs during parsing.
 */
class AntiRecafTransformerTest {

    @Test
    void emitsTrapAttributesAndBogusSignature(@TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        writeJar(input, Map.of(
                "demo/Greeter.class", buildGreeter("demo/Greeter")
        ));

        ObfuscatorConfig.Builder b = baselineDisabled();
        b.input = input;
        b.output = output;
        b.antiRecafEnabled = true;
        new Obfuscator(b.build()).run();

        // Read the obfuscated Greeter class with attribute
        // prototypes for the trap names so ASM preserves them on
        // accept() instead of silently dropping unknown attributes.
        byte[] greeterBytes = readJarEntry(output, "demo/Greeter.class");
        ClassReader cr = new ClassReader(greeterBytes);
        ClassNode cn = new ClassNode();
        Attribute[] protos = new Attribute[]{
                new ProbingAttribute(),
        };
        // ASM exposes one attribute prototype slot per entry; in
        // practice the trap names vary per build (per-JAR prefix),
        // so we register a single ProbingAttribute that matches
        // anything ending in "Trap" / "TrapM" via its overridden
        // {@code read} logic. ASM matches by exact name, so we
        // instead read the class with no prototypes and walk the
        // resulting cn.attrs list -- ASM keeps unknown attributes
        // in cn.attrs by default when a {@link ClassNode} is the
        // visitor.
        cr.accept(cn, 0);

        // Bogus class signature.
        assertNotNull(cn.signature, "AntiRecafTransformer should set a bogus class signature");
        assertTrue(cn.signature.contains("Phantom"),
                "class signature should reference a phantom class; got: " + cn.signature);
        assertTrue(cn.signature.startsWith("<T:L"),
                "class signature should declare a generic type parameter; got: " + cn.signature);

        // Class-level trap attribute.
        assertNotNull(cn.attrs, "ClassNode.attrs should be non-null after AntiRecafTransformer");
        Set<String> classAttrNames = new HashSet<>();
        for (Attribute a : cn.attrs) classAttrNames.add(a.type);
        boolean hasClassTrap = classAttrNames.stream()
                .anyMatch(n -> n.endsWith("Trap"));
        assertTrue(hasClassTrap,
                "expected a class-level Trap attribute; got attrs: " + classAttrNames);

        // Method-level trap attribute on at least one non-<init>
        // / non-<clinit> method.
        boolean hasMethodTrap = false;
        for (MethodNode mn : cn.methods) {
            if (mn.name.startsWith("<")) continue;
            if (mn.attrs == null) continue;
            for (Attribute a : mn.attrs) {
                if (a.type.endsWith("TrapM")) {
                    hasMethodTrap = true;
                    break;
                }
            }
            if (hasMethodTrap) break;
        }
        assertTrue(hasMethodTrap,
                "expected a method-level TrapM attribute on a regular method");

        // Runtime semantics still intact.
        try (java.net.URLClassLoader cl = new java.net.URLClassLoader(
                new java.net.URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            Class<?> greeter = Class.forName("demo.Greeter", true, cl);
            Object result = greeter.getMethod("greet").invoke(null);
            assertEquals("hello-world", result,
                    "anti-recaf decorations must not perturb runtime semantics");
        }
    }

    /**
     * Regression test for the bogus-signature-clobbers-superclass
     * bug: when a class with no real {@code Signature} attribute
     * extends a non-{@code Object} class, the injected bogus
     * Generic Class Signature must still encode the real
     * superclass so {@link Class#getGenericSuperclass()} returns
     * the actual parent and not {@code Object}.
     *
     * <p>The test builds {@code demo.Sub} extending
     * {@code demo.Base} (not {@code Object}), runs anti-recaf,
     * then loads the obfuscated class and asserts that
     * {@code getSuperclass()} and {@code getGenericSuperclass()}
     * both report {@code demo.Base}. Without the fix,
     * {@code getGenericSuperclass()} would return {@code Object}
     * because the JVM resolves the Signature attribute eagerly
     * for generic-aware reflection calls.
     */
    @Test
    void bogusSignaturePreservesRealSuperclass(@TempDir Path tmp) throws Exception {
        Path input = tmp.resolve("in.jar");
        Path output = tmp.resolve("out.jar");

        writeJar(input, Map.of(
                "demo/Base.class", buildBase("demo/Base"),
                "demo/Sub.class", buildSub("demo/Sub", "demo/Base")
        ));

        ObfuscatorConfig.Builder b = baselineDisabled();
        b.input = input;
        b.output = output;
        b.antiRecafEnabled = true;
        new Obfuscator(b.build()).run();

        // Confirm the injected Signature attribute on Sub references
        // demo/Base, NOT java/lang/Object.
        byte[] subBytes = readJarEntry(output, "demo/Sub.class");
        ClassNode subNode = new ClassNode();
        new ClassReader(subBytes).accept(subNode, 0);
        assertNotNull(subNode.signature, "Sub must have a bogus signature attribute");
        assertTrue(subNode.signature.contains("Ldemo/Base;"),
                "bogus signature must encode real superclass demo/Base; got: "
                        + subNode.signature);
        assertTrue(subNode.signature.contains("Phantom"),
                "bogus signature must still carry the phantom type bound; got: "
                        + subNode.signature);

        // Reflection-level confirmation: load both classes and
        // assert getGenericSuperclass() returns Base, not Object.
        try (java.net.URLClassLoader cl = new java.net.URLClassLoader(
                new java.net.URL[]{output.toUri().toURL()},
                Thread.currentThread().getContextClassLoader())) {
            Class<?> base = Class.forName("demo.Base", true, cl);
            Class<?> sub = Class.forName("demo.Sub", true, cl);
            assertEquals(base, sub.getSuperclass(),
                    "raw superclass must still be Base");
            // getGenericSuperclass() returns either a Class or a
            // ParameterizedType; in our case the bogus signature
            // declares no parameterisation on Base, so the result
            // should be the raw Class itself.
            java.lang.reflect.Type generic = sub.getGenericSuperclass();
            assertEquals(base, generic,
                    "getGenericSuperclass() must return Base, not Object; got: " + generic);
        }
    }

    private static byte[] buildBase(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null,
                "java/lang/Object", null);
        // Default constructor.
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] buildSub(String internal, String superInternal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null,
                superInternal, null);
        // Default constructor.
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, superInternal, "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        // A regular method so the method-level trap finds something
        // to attach to (otherwise Sub would have only <init>).
        MethodVisitor mv2 = cw.visitMethod(Opcodes.ACC_PUBLIC, "noop", "()V", null, null);
        mv2.visitCode();
        mv2.visitInsn(Opcodes.RETURN);
        mv2.visitMaxs(0, 0);
        mv2.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * Sentinel custom attribute. ASM uses the prototype's
     * {@code type} to match unknown attributes during
     * {@link ClassReader#accept}; with no prototype, ASM still
     * preserves unknown attributes on a {@link ClassNode} (which
     * is what we exploit -- {@code cn.attrs} ends up populated).
     */
    private static final class ProbingAttribute extends Attribute {
        ProbingAttribute() { super("ProbingAttribute"); }
    }

    private static ObfuscatorConfig.Builder baselineDisabled() {
        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.target = ObfuscatorConfig.Target.PLAIN;
        b.autoExempt = false;
        b.renamerEnabled = false;
        b.classExplodeEnabled = false;
        b.encryptedClassVaultEnabled = false;
        b.stringEncryptionEnabled = false;
        b.blobStringEnabled = false;
        b.flowEnabled = false;
        b.opaqueEnabled = false;
        b.numberEnabled = false;
        b.invokeDynamicEnabled = false;
        b.indyCallEnabled = false;
        b.indyFieldEnabled = false;
        b.junkCodeEnabled = false;
        b.bogusExceptionEnabled = false;
        b.stringConcatEnabled = false;
        b.classLiteralEnabled = false;
        b.memberShufflerEnabled = false;
        b.accessFlagsEnabled = false;
        b.localVarTableEnabled = false;
        b.localVarEnabled = false;
        b.cfgFlattenEnabled = false;
        b.fakeAnnotationsEnabled = false;
        b.sourceScrubEnabled = false;
        b.antiAgentEnabled = false;
        b.watermarkEnabled = false;
        b.antiRecafEnabled = false;
        b.verifyAfterEach = true;
        b.failOnVerifyError = true;
        return b;
    }

    private static byte[] buildGreeter(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internal, null,
                "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "greet", "()Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitLdcInsn("hello-world");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] readJarEntry(Path jar, String name) throws IOException {
        try (JarFile jf = new JarFile(jar.toFile())) {
            JarEntry je = jf.getJarEntry(name);
            assertNotNull(je, "missing entry: " + name);
            try (InputStream in = jf.getInputStream(je)) {
                return in.readAllBytes();
            }
        }
    }

    private static void writeJar(Path output, Map<String, byte[]> entries) throws IOException {
        Files.createDirectories(output.getParent());
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(output))) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                jos.putNextEntry(new JarEntry(e.getKey()));
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
    }
}
