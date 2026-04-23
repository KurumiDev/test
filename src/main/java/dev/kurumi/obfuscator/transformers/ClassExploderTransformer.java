package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Class-count inflater. For each ordinary user class in the pool, emits a
 * bundle of synthetic <b>worker classes</b> into the same package and wires
 * the original class to call one static method on each worker.
 *
 * <p>A JAR with 4 user classes becomes a JAR with ~50 classes. Each worker
 * is a self-contained {@link ClassNode} with:
 *
 * <ul>
 *   <li>A misleading class name (e.g. {@code o/LicenseGuard_3f2a1b}),
 *       drawn from the same adversarial-name pool as
 *       {@link JunkCodeInjector}.</li>
 *   <li>A static {@code long} seed field initialized in {@code <clinit>}
 *       from {@code System.nanoTime()}, making the class look runtime-bound.</li>
 *   <li>One or two honeypot methods with bodies that read system
 *       properties, probe well-known server classes via
 *       {@link Class#forName(String)}, and hash the results with SHA-256.</li>
 * </ul>
 *
 * <p>Wiring: the top of every injectable method on the <em>original</em>
 * class gains an opaque predicate of the form
 * <pre>
 *   if ((W_xxx.checkLicense_yyy(System.nanoTime()) | 1L) == 0L) throw null;
 * </pre>
 * &mdash; tautologically false at runtime, but provides a visible call-edge
 * from each original method into a different synthetic class. Dead-code
 * analysis must prove the decoy is pure before it can dismiss the branch;
 * an LLM-driven reverser narrates the cross-class call as a license /
 * anti-cheat gate first.
 *
 * <p>Worker classes are added to the pool <em>before</em> the rest of the
 * transformer pipeline runs, so string-encryption, opaque-predicates,
 * indy-call, blob-string, etc. all apply to them as well. A freshly exploded
 * JAR has the same obfuscation quality on every worker class that the
 * original had.
 */
public class ClassExploderTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(ClassExploderTransformer.class);

    /**
     * Default number of worker classes emitted per original user class.
     * 4 user classes * 12 workers = 48 new classes, so a tiny plugin
     * grows from 4 to 52 classes.
     */
    private static final int WORKERS_PER_CLASS = 12;

    private static final String[] MISLEADING_CLASS_NAMES = {
            "LicenseGuard", "AuthProbe", "HeartbeatSink", "TokenRing",
            "SignatureMatcher", "UpdateFetcher", "IntegrityAudit",
            "TelemetryBeacon", "SessionRefresher", "HwidResolver",
            "EndpointProbe", "ApiKeyRotator", "AccessAuditor",
            "CertPinner", "NonceMint", "ReplayShield",
    };

    private static final String[] MISLEADING_METHOD_ROOTS = {
            "checkLicense", "verifyLicense", "fetchUpdates",
            "reportTelemetry", "heartbeat", "validateSignature",
            "verifyIntegrity", "resolveEndpoint", "decodeToken",
            "refreshSession", "auditAccess", "computeHwid",
            "pingAuthServer", "rotateApiKey",
    };

    private static final String[] HONEYPOT_PROPS = {
            "java.vm.name", "java.vm.vendor", "java.specification.version",
            "os.name", "os.arch", "user.name", "user.dir",
            "file.separator",
    };

    private static final String[] HONEYPOT_CLASSES = {
            "org.bukkit.Bukkit",
            "org.bukkit.Server",
            "org.bukkit.plugin.PluginManager",
            "io.papermc.paper.ServerBuildInfo",
            "java.lang.management.RuntimeMXBean",
    };

    @Override
    public String name() {
        return "class-explode";
    }

    @Override
    public boolean isEnabled(ObfuscatorConfig config) {
        return config.isTransformerEnabled("class-explode");
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        // Snapshot the eligible originals before we start adding classes,
        // otherwise we'd recursively explode our own workers.
        List<ClassNode> originals = new ArrayList<>();
        for (ClassNode cn : pool.allClassNodes()) {
            if (!isEligible(cn)) continue;
            originals.add(cn);
        }

        int workersEmitted = 0;
        int wireSites = 0;

        for (ClassNode cn : originals) {
            String pkg = packageOf(cn.name);
            // Deterministic per-class RNG so repeated runs produce the same
            // worker names and bodies (important for reproducible builds
            // and mapping files).
            Random rnd = new Random(stableSeed(cn.name));

            List<WorkerRef> workers = new ArrayList<>();
            for (int i = 0; i < WORKERS_PER_CLASS; i++) {
                WorkerRef w = emitWorker(pkg, rnd, pool);
                workers.add(w);
                workersEmitted++;
            }
            wireSites += wireOriginal(cn, workers, rnd);
        }

        log.info("Exploded {} original classes into {} worker classes "
                        + "({} wire sites)",
                originals.size(), workersEmitted, wireSites);
    }

    // ------------------------------------------------------------------
    // Eligibility
    // ------------------------------------------------------------------
    private static boolean isEligible(ClassNode cn) {
        // Skip interfaces, annotations, enums, modules.
        int blockedAccess = Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION
                | Opcodes.ACC_MODULE | Opcodes.ACC_ENUM;
        if ((cn.access & blockedAccess) != 0) return false;
        // Skip already-synthetic classes so we don't explode worker
        // classes recursively if this runs twice. We also check for the
        // default-package case (no slash in the internal name).
        if (cn.name.contains("/$w_") || cn.name.startsWith("$w_")) return false;
        // Skip classes that already look like our workers. Match either
        // package-qualified names ({@code o/LicenseGuard_abcd1234}) or
        // default-package names ({@code LicenseGuard_abcd1234}).
        for (String root : MISLEADING_CLASS_NAMES) {
            if (cn.name.contains("/" + root + "_")
                    || cn.name.startsWith(root + "_")) {
                return false;
            }
        }
        return true;
    }

    private static String packageOf(String internal) {
        int slash = internal.lastIndexOf('/');
        return slash < 0 ? "" : internal.substring(0, slash);
    }

    // Deterministic 64-bit hash of a string. We roll our own so the seed
    // doesn't depend on String.hashCode()'s platform quirks.
    private static long stableSeed(String s) {
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i);
            h *= 0x100000001b3L;
        }
        return h ^ 0xDEADC0DEDEADC0DEL;
    }

    // ------------------------------------------------------------------
    // Worker class emission
    // ------------------------------------------------------------------
    private static final class WorkerRef {
        final String internalName;
        final String methodName;
        final String methodDesc = "(J)J";
        WorkerRef(String internalName, String methodName) {
            this.internalName = internalName;
            this.methodName = methodName;
        }
    }

    private WorkerRef emitWorker(String pkg, Random rnd, ClassPool pool) {
        String classRoot = MISLEADING_CLASS_NAMES[rnd.nextInt(MISLEADING_CLASS_NAMES.length)];
        String classSuffix = hex8(rnd);
        String internalName = (pkg.isEmpty() ? "" : pkg + "/")
                + classRoot + "_" + classSuffix;

        // Guard against collisions; if we picked a name that already
        // exists in the pool, rotate the suffix.
        while (pool.find(internalName) != null) {
            classSuffix = hex8(rnd);
            internalName = (pkg.isEmpty() ? "" : pkg + "/")
                    + classRoot + "_" + classSuffix;
        }

        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V17;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = internalName;
        cn.superName = "java/lang/Object";
        cn.interfaces = new ArrayList<>();
        cn.fields = new ArrayList<>();
        cn.methods = new ArrayList<>();

        // Static seed field (runtime-computed in <clinit>). Makes the
        // class look like it caches some boot-time material; decompilers
        // can't constant-fold the initializer.
        FieldNode seedField = new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                        | Opcodes.ACC_SYNTHETIC,
                "SEED", "J", null, null);
        cn.fields.add(seedField);

        // <init>()V  (we never instantiate, but give the class a valid ctor
        //             so reflective instantiation doesn't reliably crash)
        MethodNode ctor = new MethodNode(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxLocals = 1;
        ctor.maxStack = 1;
        cn.methods.add(ctor);

        // <clinit>: SEED = System.nanoTime() | 1L
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/System", "nanoTime", "()J", false));
        clinit.instructions.add(new LdcInsnNode(1L));
        clinit.instructions.add(new InsnNode(Opcodes.LOR));
        clinit.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC,
                cn.name, "SEED", "J"));
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxLocals = 0;
        clinit.maxStack = 4;
        cn.methods.add(clinit);

        // The one honeypot method we export (this is what wireOriginal
        // calls into). Public so cross-package lookup is guaranteed.
        String methodName = MISLEADING_METHOD_ROOTS[rnd.nextInt(MISLEADING_METHOD_ROOTS.length)]
                + "_" + hex8(rnd);
        MethodNode primary = buildHoneypot(methodName, cn.name, rnd);
        cn.methods.add(primary);

        // A second decoy method on the same class &mdash; never called
        // anywhere, exists only to pad the class so it looks like a
        // real utility with more than one entry point.
        String padName = MISLEADING_METHOD_ROOTS[rnd.nextInt(MISLEADING_METHOD_ROOTS.length)]
                + "_" + hex8(rnd);
        if (!padName.equals(methodName)) {
            MethodNode pad = buildHoneypot(padName, cn.name, rnd);
            cn.methods.add(pad);
        }

        pool.addClass(cn);
        return new WorkerRef(cn.name, methodName);
    }

    private static String hex8(Random rnd) {
        return String.format("%08x", rnd.nextInt() & 0xFFFFFFFF);
    }

    /**
     * Honeypot body. Same shape as {@link JunkCodeInjector#buildHoneypot},
     * but emitted on a worker class instead of inline on a user class.
     */
    private MethodNode buildHoneypot(String name, String ownerInternal, Random rnd) {
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name, "(J)J", null,
                new String[]{"java/security/NoSuchAlgorithmException"}
        );
        InsnList il = mn.instructions;

        String prop = HONEYPOT_PROPS[rnd.nextInt(HONEYPOT_PROPS.length)];
        String klass = HONEYPOT_CLASSES[rnd.nextInt(HONEYPOT_CLASSES.length)];

        il.add(new LdcInsnNode(prop));
        il.add(new LdcInsnNode(""));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "getProperty",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));

        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode afterCatch = new LabelNode();
        mn.tryCatchBlocks.add(new TryCatchBlockNode(
                tryStart, tryEnd, handler, "java/lang/Throwable"));
        il.add(tryStart);
        il.add(new LdcInsnNode(klass));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class",
                "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false));
        il.add(new InsnNode(Opcodes.POP));
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));
        il.add(tryEnd);
        il.add(new JumpInsnNode(Opcodes.GOTO, afterCatch));
        il.add(handler);
        il.add(new InsnNode(Opcodes.POP));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));
        il.add(afterCatch);

        il.add(new LdcInsnNode("SHA-256"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/security/MessageDigest", "getInstance",
                "(Ljava/lang/String;)Ljava/security/MessageDigest;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 4));

        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new FieldInsnNode(Opcodes.GETSTATIC,
                "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "getBytes", "(Ljava/nio/charset/Charset;)[B", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/security/MessageDigest", "digest", "([B)[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 5));

        // long mix = ((long) digest[0] << 56) ^ seed ^ (loaded ? FLAG : 0)
        //            ^ SEED;
        il.add(new VarInsnNode(Opcodes.ALOAD, 5));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new InsnNode(Opcodes.BALOAD));
        il.add(new InsnNode(Opcodes.I2L));
        il.add(new IntInsnNode(Opcodes.BIPUSH, 56));
        il.add(new InsnNode(Opcodes.LSHL));

        il.add(new VarInsnNode(Opcodes.LLOAD, 0));
        il.add(new InsnNode(Opcodes.LXOR));

        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        LabelNode elseBranch = new LabelNode();
        LabelNode endCond = new LabelNode();
        il.add(new JumpInsnNode(Opcodes.IFEQ, elseBranch));
        il.add(new LdcInsnNode(Long.valueOf(0xCAFEBABEDEADBEEFL)));
        il.add(new JumpInsnNode(Opcodes.GOTO, endCond));
        il.add(elseBranch);
        il.add(new InsnNode(Opcodes.LCONST_0));
        il.add(endCond);
        il.add(new InsnNode(Opcodes.LXOR));

        // mix ^= SEED
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, ownerInternal, "SEED", "J"));
        il.add(new InsnNode(Opcodes.LXOR));

        il.add(new InsnNode(Opcodes.LRETURN));

        mn.maxLocals = 8;
        mn.maxStack = 6;
        return mn;
    }

    // ------------------------------------------------------------------
    // Wiring: add cross-class opaque predicates on the original.
    // ------------------------------------------------------------------
    private int wireOriginal(ClassNode cn, List<WorkerRef> workers, Random rnd) {
        if (workers.isEmpty()) return 0;
        int sites = 0;
        // List snapshot &mdash; we must not mutate while iterating.
        List<MethodNode> methods = new ArrayList<>(cn.methods);
        for (MethodNode mn : methods) {
            if (!isMethodWireable(mn)) continue;
            WorkerRef w = workers.get(rnd.nextInt(workers.size()));
            injectWireSite(mn, w);
            sites++;
        }
        return sites;
    }

    private static boolean isMethodWireable(MethodNode mn) {
        if (mn.instructions == null || mn.instructions.size() < 3) return false;
        if (mn.name.startsWith("<")) return false;
        if (mn.name.startsWith("$obf")) return false;
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return false;
        // Don't wire honeypot decoys (prevents recursion when an exploder
        // worker tries to wire its own method).
        for (String r : MISLEADING_METHOD_ROOTS) {
            if (mn.name.startsWith(r + "_")) return false;
        }
        return true;
    }

    private static void injectWireSite(MethodNode mn, WorkerRef w) {
        AbstractInsnNode point = mn.instructions.getFirst();
        if (point == null) return;
        LabelNode skip = new LabelNode();
        InsnList il = new InsnList();

        // long x = System.nanoTime();
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "nanoTime", "()J", false));
        // long y = W_xxx.<method>(x);
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                w.internalName, w.methodName, w.methodDesc, false));
        // y | 1L
        il.add(new LdcInsnNode(1L));
        il.add(new InsnNode(Opcodes.LOR));
        // (y | 1) == 0  ?  unreachable  :  skip
        il.add(new InsnNode(Opcodes.LCONST_0));
        il.add(new InsnNode(Opcodes.LCMP));
        il.add(new JumpInsnNode(Opcodes.IFNE, skip));
        // throw null
        il.add(new InsnNode(Opcodes.ACONST_NULL));
        il.add(new InsnNode(Opcodes.ATHROW));
        il.add(skip);

        mn.instructions.insertBefore(point, il);
    }

    // Used by tests to introspect the generated naming scheme.
    public static List<String> misleadingClassRoots() {
        return Arrays.asList(MISLEADING_CLASS_NAMES);
    }
}
