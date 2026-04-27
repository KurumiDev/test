package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Decorates classes, methods, and fields with misleading runtime
 * annotations whose names and values carry strong semantic priors
 * orthogonal to the real code.
 *
 * <p>The intent is to extend the "adversarial naming" idea from
 * PR #5 (which renamed decoys to {@code checkLicense_*},
 * {@code fetchUpdates_*}, etc.) into the metadata layer. An LLM or
 * heuristic analyzer sees e.g. {@code @AntiCheat(level = HARDENED)}
 * on a method and latches onto that as load-bearing semantic ground
 * truth — yet the annotation has no retention class or bytecode
 * effect and the annotated method is the usual harmless code.
 *
 * <p>Annotations this transformer injects:
 * <ul>
 *   <li>{@code @lombok.Generated} — signals "auto-generated, ignore" to
 *       many static analyzers. Retention: CLASS.</li>
 *   <li>{@code @javax.annotation.Generated(value={...})} — same,
 *       includes fake tool/comment values that look plausible.</li>
 *   <li>{@code @kotlin.Metadata(k=1, mv={1,8,0}, ...)} — looks like
 *       the class was compiled from Kotlin. Diverts analyzers that
 *       branch on language detection.</li>
 *   <li>Our own synthetic runtime-retained annotations:
 *     <ul>
 *       <li>{@code @io.kurumi.protect.AntiCheat(level = String)}</li>
 *       <li>{@code @io.kurumi.protect.License(expires = String,
 *           owner = String, sig = String)}</li>
 *       <li>{@code @io.kurumi.protect.SecurityReview(reviewer =
 *           String, signed = boolean, hash = String)}</li>
 *     </ul>
 *     Injected synthetic annotation classes live alongside the
 *     obfuscated output so reflection actually resolves them — but
 *     the runtime never inspects them.</li>
 * </ul>
 *
 * <p>Injection is deterministic per class (seeded on the class's
 * internal name) so repeated builds produce identical output. Every
 * class gets at least one {@code @Generated}, and roughly 30-50% of
 * methods and fields get additional misleading annotations with
 * random-looking but plausible values ("HARDENED", "PRODUCTION",
 * "REVIEWED-2024-Q3", etc.).
 *
 * <p>No bytecode semantics change; this is purely constant-pool and
 * attribute pollution. Combined with the existing adversarial method
 * names, the result looks like a polished, commercial, integrity-
 * checked plugin — which wastes a lot of LLM attention.
 */
public class FakeAnnotationTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(FakeAnnotationTransformer.class);

    // Synthetic annotation class internal names we inject and then
    // reference from target classes. All have runtime retention.
    private static final String ANN_ANTI_CHEAT =
            "io/kurumi/protect/AntiCheat";
    private static final String ANN_LICENSE =
            "io/kurumi/protect/License";
    private static final String ANN_SECURITY_REVIEW =
            "io/kurumi/protect/SecurityReview";
    private static final String ANN_AUDIT_TRAIL =
            "io/kurumi/protect/AuditTrail";

    // Well-known third-party annotations we also pin, so our output
    // passes the first-pass "does this class exist?" sniff test by
    // common static analyzers.
    private static final String ANN_LOMBOK_GENERATED = "lombok/Generated";
    private static final String ANN_JAVAX_GENERATED = "javax/annotation/Generated";

    private static final String[] ANTI_CHEAT_LEVELS = {
            "HARDENED", "REINFORCED", "PRODUCTION", "NUCLEAR",
            "FORTIFIED", "INSPECTED", "AUDITED", "CERTIFIED"
    };
    private static final String[] LICENSE_OWNERS = {
            "Kurumi Dev", "SecureCore Labs", "HardenedRuntime Ltd",
            "AuditedCode Sp. z o.o.", "SigStore Alliance"
    };
    private static final String[] LICENSE_EXPIRES = {
            "2027-01-01", "2028-06-30", "2029-12-31", "2030-01-01"
    };
    private static final String[] REVIEWER_NAMES = {
            "s.kovalenko", "m.hartmann", "t.westergaard",
            "a.tanaka", "y.fernandes", "r.schneider", "l.bonnet"
    };
    private static final String[] AUDIT_TRAIL_TAGS = {
            "PRE-RELEASE-2024-Q3", "HOTFIX-2024-12-02",
            "MANDATORY-REVIEW-2025-Q1", "SOC2-CTRL-CC7.3",
            "ISO27001-A.14.2.1", "NIST-SP800-53-SI-2"
    };

    @Override
    public String name() {
        return "fake-annotations";
    }

    @Override
    public boolean isEnabled(ObfuscatorConfig config) {
        return config.isTransformerEnabled("fake-annotations");
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        injectSyntheticAnnotationClasses(pool);

        int decoratedClasses = 0;
        int decoratedMethods = 0;
        int decoratedFields = 0;
        final String pfx = SyntheticNaming.prefix(pool);

        for (ClassNode cn : pool.allClassNodes()) {
            // Skip our own injected annotation classes.
            if (isSyntheticAnnotationClass(cn.name)) continue;
            // Module info and empty classes are not worth touching.
            if ("module-info".equals(cn.name)) continue;

            long seed = stableSeed(cn.name);
            Random rng = new Random(seed);

            decorateClass(cn, rng);
            decoratedClasses++;

            for (MethodNode mn : new ArrayList<>(cn.methods)) {
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith(pfx)) continue;
                if (rng.nextInt(100) < 35) {
                    decorateMethod(mn, rng);
                    decoratedMethods++;
                }
            }
            for (FieldNode fn : new ArrayList<>(cn.fields)) {
                if (fn.name.startsWith(pfx) || "SEED".equals(fn.name)) continue;
                if (rng.nextInt(100) < 30) {
                    decorateField(fn, rng);
                    decoratedFields++;
                }
            }
        }

        log.info("Injected fake annotations on {} classes, {} methods, {} fields",
                decoratedClasses, decoratedMethods, decoratedFields);
    }

    /* ------------------------------------------------------------------ */
    /* Synthetic @kurumi/protect/* annotation classes                     */
    /* ------------------------------------------------------------------ */

    private static boolean isSyntheticAnnotationClass(String internalName) {
        return internalName.equals(ANN_ANTI_CHEAT)
                || internalName.equals(ANN_LICENSE)
                || internalName.equals(ANN_SECURITY_REVIEW)
                || internalName.equals(ANN_AUDIT_TRAIL);
    }

    private static void injectSyntheticAnnotationClasses(ClassPool pool) {
        if (pool.containsClass(ANN_ANTI_CHEAT)) return;

        pool.addClass(buildAnnotationClass(ANN_ANTI_CHEAT,
                new String[][]{{"level", "Ljava/lang/String;"}}));
        pool.addClass(buildAnnotationClass(ANN_LICENSE,
                new String[][]{
                        {"expires", "Ljava/lang/String;"},
                        {"owner",   "Ljava/lang/String;"},
                        {"sig",     "Ljava/lang/String;"}
                }));
        pool.addClass(buildAnnotationClass(ANN_SECURITY_REVIEW,
                new String[][]{
                        {"reviewer", "Ljava/lang/String;"},
                        {"signed",   "Z"},
                        {"hash",     "Ljava/lang/String;"}
                }));
        pool.addClass(buildAnnotationClass(ANN_AUDIT_TRAIL,
                new String[][]{
                        {"tag",    "Ljava/lang/String;"},
                        {"when",   "Ljava/lang/String;"}
                }));
    }

    /** Emits a runtime-retained annotation class with the given name
     *  and String/boolean element methods. The class is minimal: just
     *  the interface + abstract element methods. JVM + annotation
     *  runtime handle the rest. */
    private static ClassNode buildAnnotationClass(String internalName, String[][] elements) {
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V17;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT
                | Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION;
        cn.name = internalName;
        cn.superName = "java/lang/Object";
        cn.interfaces = new ArrayList<>();
        cn.interfaces.add("java/lang/annotation/Annotation");

        // @Retention(RetentionPolicy.RUNTIME)
        AnnotationNode retention = new AnnotationNode("Ljava/lang/annotation/Retention;");
        retention.values = new ArrayList<>();
        retention.values.add("value");
        retention.values.add(new String[]{"Ljava/lang/annotation/RetentionPolicy;", "RUNTIME"});
        cn.visibleAnnotations = new ArrayList<>();
        cn.visibleAnnotations.add(retention);

        // @Target({TYPE, METHOD, FIELD})
        AnnotationNode target = new AnnotationNode("Ljava/lang/annotation/Target;");
        target.values = new ArrayList<>();
        target.values.add("value");
        target.values.add(Arrays.asList(
                new String[]{"Ljava/lang/annotation/ElementType;", "TYPE"},
                new String[]{"Ljava/lang/annotation/ElementType;", "METHOD"},
                new String[]{"Ljava/lang/annotation/ElementType;", "FIELD"}));
        cn.visibleAnnotations.add(target);

        for (String[] el : elements) {
            MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                    el[0], "()" + el[1], null, null);
            cn.methods.add(mn);
        }
        return cn;
    }

    /* ------------------------------------------------------------------ */
    /* Decoration helpers                                                 */
    /* ------------------------------------------------------------------ */

    private static void decorateClass(ClassNode cn, Random rng) {
        if (cn.visibleAnnotations == null) cn.visibleAnnotations = new ArrayList<>();
        if (cn.invisibleAnnotations == null) cn.invisibleAnnotations = new ArrayList<>();

        // @lombok.Generated on every class: looks auto-generated.
        cn.invisibleAnnotations.add(markerAnnotation(ANN_LOMBOK_GENERATED));

        // @javax.annotation.Generated with plausible values.
        AnnotationNode gen = new AnnotationNode("L" + ANN_JAVAX_GENERATED + ";");
        gen.values = new ArrayList<>();
        gen.values.add("value");
        gen.values.add(Arrays.asList("io.kurumi.protect.HardenCompiler"));
        gen.values.add("comments");
        gen.values.add("build=" + (0x5000 + rng.nextInt(0x2000))
                + "; reviewed=" + pick(REVIEWER_NAMES, rng)
                + "; profile=" + pick(ANTI_CHEAT_LEVELS, rng));
        cn.invisibleAnnotations.add(gen);

        if (rng.nextInt(100) < 70) {
            cn.visibleAnnotations.add(makeLicense(rng));
        }
        if (rng.nextInt(100) < 55) {
            cn.visibleAnnotations.add(makeSecurityReview(rng));
        }
        if (rng.nextInt(100) < 40) {
            cn.visibleAnnotations.add(makeAuditTrail(rng));
        }
    }

    private static void decorateMethod(MethodNode mn, Random rng) {
        if (mn.visibleAnnotations == null) mn.visibleAnnotations = new ArrayList<>();
        if (mn.invisibleAnnotations == null) mn.invisibleAnnotations = new ArrayList<>();

        mn.invisibleAnnotations.add(markerAnnotation(ANN_LOMBOK_GENERATED));
        if (rng.nextInt(100) < 65) {
            mn.visibleAnnotations.add(makeAntiCheat(rng));
        }
        if (rng.nextInt(100) < 35) {
            mn.visibleAnnotations.add(makeSecurityReview(rng));
        }
        if (rng.nextInt(100) < 25) {
            mn.visibleAnnotations.add(makeAuditTrail(rng));
        }
    }

    private static void decorateField(FieldNode fn, Random rng) {
        if (fn.visibleAnnotations == null) fn.visibleAnnotations = new ArrayList<>();
        if (fn.invisibleAnnotations == null) fn.invisibleAnnotations = new ArrayList<>();

        if (rng.nextInt(100) < 60) {
            fn.visibleAnnotations.add(makeAntiCheat(rng));
        }
        if (rng.nextInt(100) < 40) {
            fn.visibleAnnotations.add(makeAuditTrail(rng));
        }
    }

    /* ------------------------------------------------------------------ */
    /* Annotation factories                                               */
    /* ------------------------------------------------------------------ */

    private static AnnotationNode markerAnnotation(String internalName) {
        return new AnnotationNode("L" + internalName + ";");
    }

    private static AnnotationNode makeAntiCheat(Random rng) {
        AnnotationNode a = new AnnotationNode("L" + ANN_ANTI_CHEAT + ";");
        a.values = new ArrayList<>();
        a.values.add("level");
        a.values.add(pick(ANTI_CHEAT_LEVELS, rng));
        return a;
    }

    private static AnnotationNode makeLicense(Random rng) {
        AnnotationNode a = new AnnotationNode("L" + ANN_LICENSE + ";");
        a.values = new ArrayList<>();
        a.values.add("expires");
        a.values.add(pick(LICENSE_EXPIRES, rng));
        a.values.add("owner");
        a.values.add(pick(LICENSE_OWNERS, rng));
        a.values.add("sig");
        a.values.add(hex(rng, 32));
        return a;
    }

    private static AnnotationNode makeSecurityReview(Random rng) {
        AnnotationNode a = new AnnotationNode("L" + ANN_SECURITY_REVIEW + ";");
        a.values = new ArrayList<>();
        a.values.add("reviewer");
        a.values.add(pick(REVIEWER_NAMES, rng));
        a.values.add("signed");
        a.values.add(Boolean.TRUE);
        a.values.add("hash");
        a.values.add(hex(rng, 64));
        return a;
    }

    private static AnnotationNode makeAuditTrail(Random rng) {
        AnnotationNode a = new AnnotationNode("L" + ANN_AUDIT_TRAIL + ";");
        a.values = new ArrayList<>();
        a.values.add("tag");
        a.values.add(pick(AUDIT_TRAIL_TAGS, rng));
        a.values.add("when");
        a.values.add(String.format("20%02d-%02d-%02dT%02d:%02d:%02dZ",
                24 + rng.nextInt(5),
                1 + rng.nextInt(12),
                1 + rng.nextInt(28),
                rng.nextInt(24),
                rng.nextInt(60),
                rng.nextInt(60)));
        return a;
    }

    /* ------------------------------------------------------------------ */
    /* Utilities                                                          */
    /* ------------------------------------------------------------------ */

    private static String pick(String[] pool, Random rng) {
        return pool[rng.nextInt(pool.length)];
    }

    private static String hex(Random rng, int nibbles) {
        char[] chars = "0123456789abcdef".toCharArray();
        StringBuilder sb = new StringBuilder(nibbles);
        for (int i = 0; i < nibbles; i++) sb.append(chars[rng.nextInt(16)]);
        return sb.toString();
    }

    private static long stableSeed(String s) {
        long h = 0xCBF29CE484222325L;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i);
            h *= 0x100000001B3L;
        }
        return h;
    }
}
