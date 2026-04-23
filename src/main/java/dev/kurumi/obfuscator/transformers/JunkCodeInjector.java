package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * Injects decoy methods that look like real business logic but are never
 * actually invoked. Two flavors are emitted per class:
 *
 * <ol>
 *   <li><b>Light decoy</b> &mdash; a {@code StringBuilder}-driven body that
 *       hashes a pile of fake tokens and returns a long derived from the
 *       argument. Cheap to generate, plausible at a glance.</li>
 *   <li><b>Honeypot</b> &mdash; a body that <em>reads the runtime
 *       environment</em> (system properties, Bukkit class probes,
 *       {@code MessageDigest}) and performs what looks like an
 *       integrity / license / telemetry computation. An LLM-based
 *       reverser who prioritizes method bodies that touch
 *       {@code System.getProperty}, {@code Class.forName} and
 *       {@code MessageDigest.getInstance("SHA-256")} will allocate
 *       context window to parsing these bodies, but the output is
 *       never consumed by real code.</li>
 * </ol>
 *
 * <p><b>Adversarial naming.</b> Method names are drawn from a pool of
 * misleading domain terms &mdash; {@code checkLicense_XXX},
 * {@code fetchUpdates_XXX}, {@code heartbeat_XXX}, etc. &mdash; which
 * exploits LLM priors: a model that associates {@code checkLicense}
 * with network calls and cryptographic verification will try to fit
 * that narrative onto the decoy body. Neutral names like
 * {@code $obfJk<hash>} don't trip these priors.
 *
 * <p>Decoys are marked {@code ACC_SYNTHETIC | ACC_PRIVATE} so JVM
 * tooling recognizes them as compiler-generated. They are well-formed
 * bytecode and survive {@code CheckClassAdapter.verify}.
 */
public class JunkCodeInjector implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(JunkCodeInjector.class);

    /**
     * Misleading domain-specific method-name roots. Exposed to
     * {@link OpaquePredicateTransformer} so it can recognize honeypot
     * methods emitted on the same class and wire them into opaque
     * predicates.
     */
    public static String[] MISLEADING_NAMES() {
        return MISLEADING_NAMES.clone();
    }

    private static final String[] MISLEADING_NAMES = {
            "checkLicense",
            "verifyLicense",
            "fetchUpdates",
            "reportTelemetry",
            "heartbeat",
            "validateSignature",
            "verifyIntegrity",
            "resolveEndpoint",
            "decodeToken",
            "refreshSession",
            "auditAccess",
            "computeHwid",
            "pingAuthServer",
            "rotateApiKey",
    };

    /** System properties whose read is plausible for license/anti-cheat logic. */
    private static final String[] HONEYPOT_PROPS = {
            "java.vm.name",
            "java.vm.vendor",
            "java.specification.version",
            "os.name",
            "os.arch",
            "user.name",
            "user.dir",
            "file.separator",
    };

    /** Fake security-looking class names that Bukkit-adjacent reversers recognize. */
    private static final String[] HONEYPOT_CLASSES = {
            "org.bukkit.Bukkit",
            "org.bukkit.Server",
            "org.bukkit.plugin.PluginManager",
            "io.papermc.paper.ServerBuildInfo",
            "java.lang.management.RuntimeMXBean",
    };

    @Override
    public String name() {
        return "junk-code";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        Random rnd = new Random(0xDEADC0DEL);
        int injected = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) continue;
            int n = 2 + rnd.nextInt(2);
            for (int i = 0; i < n; i++) {
                String suffix = Integer.toHexString(rnd.nextInt()).replace("-", "");
                // Alternate between light and honeypot decoys, and keep one
                // $obfJk neutral name per class so that anyone grepping for
                // the old pattern still finds junk (but not only junk).
                boolean honeypot = rnd.nextBoolean();
                String root = honeypot
                        ? MISLEADING_NAMES[rnd.nextInt(MISLEADING_NAMES.length)]
                        : "$obfJk";
                String name = honeypot ? root + "_" + suffix : root + suffix;
                MethodNode decoy = honeypot
                        ? buildHoneypot(name, rnd)
                        : buildDecoy(name, rnd);
                // Uniqueness guard: if a class already has this name (very
                // unlikely given the hash suffix), skip.
                boolean exists = false;
                for (MethodNode m : cn.methods) {
                    if (m.name.equals(decoy.name) && m.desc.equals(decoy.desc)) { exists = true; break; }
                }
                if (exists) continue;
                cn.methods.add(decoy);
                injected++;
            }
        }
        log.info("Injected {} junk methods across {} classes", injected, pool.allClassNodes().size());
    }

    private MethodNode buildDecoy(String name, Random rnd) {
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name,
                "(J)J",
                null,
                null
        );
        InsnList il = mn.instructions;
        // StringBuilder to look like business-logic
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder",
                "<init>", "()V", false));
        int stores = 2 + rnd.nextInt(3);
        for (int i = 0; i < stores; i++) {
            il.add(new LdcInsnNode(fakeString(rnd)));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                    "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
            il.add(new VarInsnNode(Opcodes.LLOAD, 0));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                    "append", "(J)Ljava/lang/StringBuilder;", false));
        }
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "toString", "()Ljava/lang/String;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "hashCode", "()I", false));
        il.add(new InsnNode(Opcodes.I2L));
        // Mix with input
        il.add(new VarInsnNode(Opcodes.LLOAD, 0));
        il.add(new InsnNode(Opcodes.LXOR));
        il.add(new LdcInsnNode(rnd.nextLong()));
        il.add(new InsnNode(Opcodes.LADD));
        il.add(new InsnNode(Opcodes.LRETURN));
        mn.maxLocals = 2;
        mn.maxStack = 6;
        return mn;
    }

    /**
     * Builds a {@code (J)J} body whose bytecode looks like a real
     * license / integrity / telemetry routine: it reads a system
     * property, probes whether a well-known server class is loadable,
     * hashes the two together with SHA-256, and XORs the result with
     * the long argument. The final value is {@code LRETURN}ed but
     * every caller of this method is itself junk, so the value never
     * reaches real code.
     *
     * <pre>
     * private static long &lt;name&gt;(long seed) {
     *   String prop = System.getProperty("&lt;HONEYPOT_PROP&gt;", "");
     *   boolean loaded;
     *   try {
     *     Class.forName("&lt;HONEYPOT_CLASS&gt;");
     *     loaded = true;
     *   } catch (Throwable t) {
     *     loaded = false;
     *   }
     *   MessageDigest md = MessageDigest.getInstance("SHA-256");
     *   byte[] digest = md.digest(prop.getBytes(StandardCharsets.UTF_8));
     *   long mix = ((long) digest[0] &lt;&lt; 56) ^ seed ^ (loaded ? 0xCAFEBABEDEADBEEFL : 0L);
     *   return mix;
     * }
     * </pre>
     */
    private MethodNode buildHoneypot(String name, Random rnd) {
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name,
                "(J)J",
                null,
                new String[]{"java/security/NoSuchAlgorithmException"}
        );
        InsnList il = mn.instructions;

        // Locals:
        //   0..1 = seed (long)
        //   2    = prop (String)
        //   3    = loaded (int)
        //   4    = md (MessageDigest)
        //   5    = digest (byte[])
        //   6..7 = mix (long)

        String prop = HONEYPOT_PROPS[rnd.nextInt(HONEYPOT_PROPS.length)];
        String klass = HONEYPOT_CLASSES[rnd.nextInt(HONEYPOT_CLASSES.length)];

        // String prop = System.getProperty(prop, "");
        il.add(new LdcInsnNode(prop));
        il.add(new LdcInsnNode(""));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "getProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // boolean loaded;
        // try { Class.forName(klass); loaded = true; }
        // catch (Throwable) { loaded = false; }
        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode afterCatch = new LabelNode();
        mn.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(
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
        il.add(new InsnNode(Opcodes.POP)); // discard the exception
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));
        il.add(afterCatch);

        // MessageDigest md = MessageDigest.getInstance("SHA-256");
        il.add(new LdcInsnNode("SHA-256"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/security/MessageDigest",
                "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 4));

        // byte[] digest = md.digest(prop.getBytes(StandardCharsets.UTF_8));
        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC,
                "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "getBytes", "(Ljava/nio/charset/Charset;)[B", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/security/MessageDigest",
                "digest", "([B)[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 5));

        // long mix = ((long) digest[0] << 56) ^ seed ^ (loaded ? 0xCAFEBABEDEADBEEFL : 0L);
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

        il.add(new VarInsnNode(Opcodes.LSTORE, 6));
        il.add(new VarInsnNode(Opcodes.LLOAD, 6));
        il.add(new InsnNode(Opcodes.LRETURN));

        mn.maxLocals = 8;
        mn.maxStack = 6;
        return mn;
    }

    private static final String[] FAKE_STRINGS = {
            "session-", "nonce=", "rev:", "hash/", "mac:",
            "etag-", "k=", "iv:", "q-", "tenant/"
    };

    private static String fakeString(Random rnd) {
        return FAKE_STRINGS[rnd.nextInt(FAKE_STRINGS.length)];
    }
}
