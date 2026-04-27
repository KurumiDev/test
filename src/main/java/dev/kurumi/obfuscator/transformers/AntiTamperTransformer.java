package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.FrameComputingClassWriterFactory;
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
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Anti-tamper integrity verification.
 *
 * <p>Threat model: an attacker uses Recaf (or a similar bytecode
 * editor) to patch a method in the obfuscated JAR -- e.g. replacing
 * a license check or removing a {@link AntiAgentTransformer
 * anti-agent guard} -- and re-saves the JAR. We want the modified
 * JAR to refuse to run.
 *
 * <p>Strategy:
 * <ol>
 *   <li>At obfuscation time, after every other transformer has run,
 *       serialise each user class to its final bytes via the
 *       pool-aware {@link FrameComputingClassWriterFactory} and
 *       compute SHA-256 over those bytes.</li>
 *   <li>Build a per-build manifest -- a flat UTF-8 listing of
 *       {@code &lt;internal-name&gt; SP &lt;base64-sha256&gt; NL}
 *       lines -- and HMAC-SHA-256 it with a 32-byte key drawn from
 *       {@link SecureRandom}.</li>
 *   <li>Embed the manifest, the HMAC, and the HMAC key as Base64
 *       constant strings inside a synthetic
 *       {@code $&lt;prefix&gt;IntegritySvc_&lt;hex&gt;} helper class.</li>
 *   <li>Inject {@code INVOKESTATIC IntegritySvc.touch()V} at the
 *       very start of every user class's {@code &lt;clinit&gt;}.
 *       The first user class loaded triggers IntegritySvc's
 *       {@code &lt;clinit&gt;}, which calls {@code verifyAll()}.</li>
 *   <li>{@code verifyAll()} HMAC-checks the manifest, then for every
 *       listed class loads its bytes via
 *       {@code getResourceAsStream}, SHA-256s them, and compares to
 *       the expected hash. On any mismatch (or any thrown exception
 *       from the verification path), {@link Runtime#halt(int)} with
 *       status 1.</li>
 * </ol>
 *
 * <p>Limits: a determined attacker can patch out the {@code touch()}
 * call sites <i>and</i> the IntegritySvc class itself. The defence is
 * to layer this with the existing
 * {@link StringEncryptionTransformer string-encryption} and
 * {@link IndyCallTransformer indy-call} passes -- IntegritySvc's
 * literals get encrypted alongside everything else, and most of its
 * method calls go through {@code invokedynamic} bootstraps. None of
 * this is invincible, but it raises the bar against trivial
 * modifications.
 *
 * <p>Why not embed each hash in its own class as a {@code ConstantValue}
 * attribute and self-verify? That's the cleaner design at first
 * glance, but it requires the runtime verifier to parse the class
 * file, locate the hash field, zero it, and re-hash. That implies
 * shipping ASM (or an equivalent class-file parser) inside every
 * obfuscated JAR -- an unacceptable runtime dependency. Manifesting
 * to a single helper class avoids this entirely.
 */
public class AntiTamperTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(AntiTamperTransformer.class);

    private static final String SVC_INFIX = "IntegritySvc_";
    private static final String TOUCH_NAME = "touch";
    private static final String FIELD_MANIFEST = "M";
    private static final String FIELD_HMAC = "S";
    private static final String FIELD_KEY = "K";
    private static final String FIELD_VERIFIED = "V";

    @Override
    public String name() {
        return "anti-tamper";
    }

    @Override
    public boolean isEnabled(ObfuscatorConfig config) {
        return config.isTransformerEnabled("anti-tamper");
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        String prefix = SyntheticNaming.prefix(pool);
        String svcName = prefix + SVC_INFIX + Integer.toHexString(pool.size() ^ 0x7E517A0B);

        // Per-build random HMAC key. Embedded in the helper class
        // exactly once. Different on every obfuscation run so two
        // outputs of the same input have no shared verification key.
        byte[] hmacKey = new byte[32];
        new SecureRandom().nextBytes(hmacKey);

        ClassNode svc = buildIntegritySvcClass(svcName, hmacKey);
        pool.addClass(svc);

        int instrumented = 0;
        List<ClassNode> snapshot = new ArrayList<>(pool.allClassNodes());
        for (ClassNode cn : snapshot) {
            if (cn == svc) continue;
            if (cn.name.equals(svcName)) continue;
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
            if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) continue;
            if ((cn.access & Opcodes.ACC_MODULE) != 0) continue;
            // Same exemption as the anti-agent guard: vault workers
            // run before this helper class is loadable.
            if (cn.name.contains("ClassVault_") || cn.name.contains("$obfClassVault_")) continue;
            if (injectTouchCall(cn, svcName)) {
                instrumented++;
            }
        }

        // Pre-serialise every user class (excluding the helper) to
        // its final bytes and compute SHA-256. We use the same
        // pool-aware writer factory that JarWriter will use, so the
        // bytes we hash here are byte-for-byte identical to what the
        // runtime classloader will see when it loads the class.
        FrameComputingClassWriterFactory factory = new FrameComputingClassWriterFactory(pool);
        StringBuilder manifest = new StringBuilder();
        for (ClassNode cn : pool.allClassNodes()) {
            if (cn == svc) continue;
            if (cn.name.equals(svcName)) continue;
            byte[] bytes = factory.toBytes(cn);
            String sha = Base64.getEncoder().encodeToString(sha256(bytes));
            manifest.append(cn.name).append(' ').append(sha).append('\n');
        }
        byte[] manifestBytes = manifest.toString().getBytes(StandardCharsets.UTF_8);
        byte[] hmacBytes = hmacSha256(manifestBytes, hmacKey);

        String manifestB64 = Base64.getEncoder().encodeToString(manifestBytes);
        String hmacB64 = Base64.getEncoder().encodeToString(hmacBytes);
        String keyB64 = Base64.getEncoder().encodeToString(hmacKey);
        for (FieldNode fn : svc.fields) {
            switch (fn.name) {
                case FIELD_MANIFEST -> fn.value = manifestB64;
                case FIELD_HMAC -> fn.value = hmacB64;
                case FIELD_KEY -> fn.value = keyB64;
                default -> { /* keep placeholder */ }
            }
        }

        log.info("Anti-tamper: instrumented {} classes, manifest covers {} entries ({})",
                instrumented, manifest.toString().split("\n", -1).length - 1, svcName);
    }

    /* -------------------------- helper class ------------------------- */

    private static ClassNode buildIntegritySvcClass(String internalName, byte[] hmacKey) {
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V17;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = internalName;
        cn.superName = "java/lang/Object";
        cn.interfaces = new ArrayList<>();
        cn.fields = new ArrayList<>();
        cn.methods = new ArrayList<>();

        // Three String fields with placeholder ConstantValue
        // attributes; transform() rewrites the values once the
        // manifest has been computed. Field names are kept very
        // short (single character) so the renamer + flow-obf
        // pipeline doesn't waste room on them.
        cn.fields.add(constField(FIELD_MANIFEST, ""));
        cn.fields.add(constField(FIELD_HMAC, ""));
        cn.fields.add(constField(FIELD_KEY, Base64.getEncoder().encodeToString(hmacKey)));

        cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE | Opcodes.ACC_SYNTHETIC,
                FIELD_VERIFIED, "Z", null, null));

        cn.methods.add(buildCtor());
        cn.methods.add(buildTouchMethod());
        cn.methods.add(buildVerifyAllMethod(internalName));
        cn.methods.add(buildClinit(internalName));

        return cn;
    }

    private static FieldNode constField(String name, String value) {
        return new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                name, "Ljava/lang/String;", null, value);
    }

    private static MethodNode buildCtor() {
        MethodNode mn = new MethodNode(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
        InsnList il = new InsnList();
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        il.add(new InsnNode(Opcodes.RETURN));
        mn.instructions = il;
        mn.maxStack = 1;
        mn.maxLocals = 1;
        return mn;
    }

    private static MethodNode buildTouchMethod() {
        // Empty body. Its only purpose is to be invoked from user
        // class <clinit>s -- the first call triggers IntegritySvc's
        // own <clinit>, which is what actually performs verification.
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                TOUCH_NAME, "()V", null, null);
        InsnList il = new InsnList();
        il.add(new InsnNode(Opcodes.RETURN));
        mn.instructions = il;
        mn.maxStack = 0;
        mn.maxLocals = 0;
        return mn;
    }

    private static MethodNode buildClinit(String selfName) {
        MethodNode mn = new MethodNode(
                Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList il = new InsnList();
        // verifyAll(); return;
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, selfName, "verifyAll", "()V", false));
        il.add(new InsnNode(Opcodes.RETURN));
        mn.instructions = il;
        mn.maxStack = 0;
        mn.maxLocals = 0;
        return mn;
    }

    /**
     * Emits the {@code verifyAll()} body. Pseudocode:
     *
     * <pre>{@code
     * try {
     *     byte[] manifestBytes = Base64.getDecoder().decode(MANIFEST);
     *     byte[] expectedHmac  = Base64.getDecoder().decode(HMAC);
     *     byte[] keyBytes      = Base64.getDecoder().decode(KEY);
     *     Mac mac = Mac.getInstance("HmacSHA256");
     *     mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
     *     byte[] computed = mac.doFinal(manifestBytes);
     *     if (!MessageDigest.isEqual(computed, expectedHmac)) Runtime.getRuntime().halt(1);
     *
     *     ClassLoader cl = SVC.class.getClassLoader();
     *     for (String line : new String(manifestBytes, UTF_8).split("\n")) {
     *         if (line.isEmpty()) continue;
     *         int sp = line.indexOf(' ');
     *         String className = line.substring(0, sp);
     *         String expectedB64 = line.substring(sp + 1);
     *         byte[] expectedSha = Base64.getDecoder().decode(expectedB64);
     *         InputStream in = cl.getResourceAsStream(className + ".class");
     *         if (in == null) Runtime.getRuntime().halt(1);
     *         byte[] classBytes = in.readAllBytes();
     *         MessageDigest md = MessageDigest.getInstance("SHA-256");
     *         byte[] actualSha = md.digest(classBytes);
     *         if (!MessageDigest.isEqual(actualSha, expectedSha)) Runtime.getRuntime().halt(1);
     *     }
     *     VERIFIED = true;
     * } catch (Throwable t) {
     *     Runtime.getRuntime().halt(1);
     * }
     * }</pre>
     */
    private static MethodNode buildVerifyAllMethod(String selfName) {
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                "verifyAll", "()V", null, null);
        InsnList il = new InsnList();
        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode end = new LabelNode();
        il.add(tryStart);

        // Local 0 = manifestBytes
        // Local 1 = expectedHmac
        // Local 2 = keyBytes
        // Local 3 = mac
        // Local 4 = computedHmac
        // Local 5 = manifestStr
        // Local 6 = lines (String[])
        // Local 7 = i (int)
        // Local 8 = line
        // Local 9 = sp
        // Local 10 = className
        // Local 11 = expectedSha
        // Local 12 = in
        // Local 13 = classBytes
        // Local 14 = actualSha
        // Local 15 = cl

        // manifestBytes = Base64.decode(MANIFEST)
        emitDecodeFieldB64(il, selfName, FIELD_MANIFEST);
        il.add(new VarInsnNode(Opcodes.ASTORE, 0));

        // expectedHmac = Base64.decode(HMAC)
        emitDecodeFieldB64(il, selfName, FIELD_HMAC);
        il.add(new VarInsnNode(Opcodes.ASTORE, 1));

        // keyBytes = Base64.decode(KEY)
        emitDecodeFieldB64(il, selfName, FIELD_KEY);
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // mac = Mac.getInstance("HmacSHA256")
        il.add(new LdcInsnNode("HmacSHA256"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "javax/crypto/Mac", "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Mac;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 3));

        // mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"))
        il.add(new VarInsnNode(Opcodes.ALOAD, 3));
        il.add(new TypeInsnNode(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new LdcInsnNode("HmacSHA256"));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec",
                "<init>", "([BLjava/lang/String;)V", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "javax/crypto/Mac", "init",
                "(Ljava/security/Key;)V", false));

        // computed = mac.doFinal(manifestBytes)
        il.add(new VarInsnNode(Opcodes.ALOAD, 3));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "javax/crypto/Mac", "doFinal",
                "([B)[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 4));

        // if (!MessageDigest.isEqual(computed, expectedHmac)) halt(1)
        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/security/MessageDigest", "isEqual",
                "([B[B)Z", false));
        LabelNode hmacOk = new LabelNode();
        il.add(new JumpInsnNode(Opcodes.IFNE, hmacOk));
        emitHalt(il, 1);
        il.add(hmacOk);

        // cl = $svc.class.getClassLoader()
        il.add(new LdcInsnNode(org.objectweb.asm.Type.getObjectType(selfName)));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader",
                "()Ljava/lang/ClassLoader;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 15));

        // manifestStr = new String(manifestBytes, UTF_8)
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC,
                "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>",
                "([BLjava/nio/charset/Charset;)V", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 5));

        // lines = manifestStr.split("\n")
        il.add(new VarInsnNode(Opcodes.ALOAD, 5));
        il.add(new LdcInsnNode("\n"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "split",
                "(Ljava/lang/String;)[Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 6));

        // i = 0
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, 7));

        LabelNode loopHead = new LabelNode();
        LabelNode loopExit = new LabelNode();
        LabelNode loopContinue = new LabelNode();
        il.add(loopHead);
        // if (i >= lines.length) goto loopExit
        il.add(new VarInsnNode(Opcodes.ILOAD, 7));
        il.add(new VarInsnNode(Opcodes.ALOAD, 6));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopExit));

        // line = lines[i]
        il.add(new VarInsnNode(Opcodes.ALOAD, 6));
        il.add(new VarInsnNode(Opcodes.ILOAD, 7));
        il.add(new InsnNode(Opcodes.AALOAD));
        il.add(new VarInsnNode(Opcodes.ASTORE, 8));

        // if (line.isEmpty()) continue
        il.add(new VarInsnNode(Opcodes.ALOAD, 8));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "isEmpty", "()Z", false));
        il.add(new JumpInsnNode(Opcodes.IFNE, loopContinue));

        // sp = line.indexOf(' ')
        il.add(new VarInsnNode(Opcodes.ALOAD, 8));
        il.add(new IntInsnNode(Opcodes.BIPUSH, 32));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf",
                "(I)I", false));
        il.add(new VarInsnNode(Opcodes.ISTORE, 9));

        // if (sp < 0) halt(1)
        il.add(new VarInsnNode(Opcodes.ILOAD, 9));
        LabelNode haveSp = new LabelNode();
        il.add(new JumpInsnNode(Opcodes.IFGE, haveSp));
        emitHalt(il, 1);
        il.add(haveSp);

        // className = line.substring(0, sp)
        il.add(new VarInsnNode(Opcodes.ALOAD, 8));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ILOAD, 9));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
                "(II)Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 10));

        // expectedSha = Base64.decode(line.substring(sp + 1))
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder",
                "()Ljava/util/Base64$Decoder;", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, 8));
        il.add(new VarInsnNode(Opcodes.ILOAD, 9));
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
                "(I)Ljava/lang/String;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder", "decode",
                "(Ljava/lang/String;)[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 11));

        // in = cl.getResourceAsStream(className + ".class")
        il.add(new VarInsnNode(Opcodes.ALOAD, 15));
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder",
                "<init>", "()V", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, 10));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        il.add(new LdcInsnNode(".class"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                "()Ljava/lang/String;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader",
                "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 12));

        // if (in == null) halt(1)
        il.add(new VarInsnNode(Opcodes.ALOAD, 12));
        LabelNode haveIn = new LabelNode();
        il.add(new JumpInsnNode(Opcodes.IFNONNULL, haveIn));
        emitHalt(il, 1);
        il.add(haveIn);

        // classBytes = in.readAllBytes()
        il.add(new VarInsnNode(Opcodes.ALOAD, 12));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/io/InputStream",
                "readAllBytes", "()[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 13));

        // actualSha = MessageDigest.getInstance("SHA-256").digest(classBytes)
        il.add(new LdcInsnNode("SHA-256"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/security/MessageDigest",
                "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, 13));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/security/MessageDigest",
                "digest", "([B)[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 14));

        // if (!MessageDigest.isEqual(actualSha, expectedSha)) halt(1)
        il.add(new VarInsnNode(Opcodes.ALOAD, 14));
        il.add(new VarInsnNode(Opcodes.ALOAD, 11));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/security/MessageDigest",
                "isEqual", "([B[B)Z", false));
        LabelNode shaOk = new LabelNode();
        il.add(new JumpInsnNode(Opcodes.IFNE, shaOk));
        emitHalt(il, 1);
        il.add(shaOk);

        // i++
        il.add(loopContinue);
        il.add(new org.objectweb.asm.tree.IincInsnNode(7, 1));
        il.add(new JumpInsnNode(Opcodes.GOTO, loopHead));
        il.add(loopExit);

        // VERIFIED = true
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new FieldInsnNode(Opcodes.PUTSTATIC, selfName, FIELD_VERIFIED, "Z"));
        il.add(tryEnd);
        il.add(new JumpInsnNode(Opcodes.GOTO, end));

        // catch (Throwable t) { Runtime.getRuntime().halt(1); }
        il.add(handler);
        il.add(new InsnNode(Opcodes.POP)); // discard exception
        emitHalt(il, 1);
        il.add(end);
        il.add(new InsnNode(Opcodes.RETURN));

        mn.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(
                tryStart, tryEnd, handler, "java/lang/Throwable"));
        mn.instructions = il;
        mn.maxStack = 6;
        mn.maxLocals = 16;
        return mn;
    }

    /** Emits {@code Base64.getDecoder().decode(<svc>.<field>)} -> byte[]. */
    private static void emitDecodeFieldB64(InsnList il, String selfName, String field) {
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder",
                "()Ljava/util/Base64$Decoder;", false));
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, selfName, field, "Ljava/lang/String;"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder", "decode",
                "(Ljava/lang/String;)[B", false));
    }

    /** Emits {@code Runtime.getRuntime().halt(status); return;} -- terminal. */
    private static void emitHalt(InsnList il, int status) {
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                "()Ljava/lang/Runtime;", false));
        il.add(new IntInsnNode(Opcodes.BIPUSH, status));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "halt", "(I)V", false));
        il.add(new InsnNode(Opcodes.RETURN));
    }

    /* -------------------------- touch injection ----------------------- */

    private static boolean injectTouchCall(ClassNode cn, String svcName) {
        MethodNode clinit = null;
        for (MethodNode mn : cn.methods) {
            if ("<clinit>".equals(mn.name)) {
                clinit = mn;
                break;
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions = new InsnList();
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(clinit);
        }
        InsnList prelude = new InsnList();
        prelude.add(new MethodInsnNode(Opcodes.INVOKESTATIC, svcName, TOUCH_NAME, "()V", false));
        AbstractInsnNode first = clinit.instructions.getFirst();
        if (first == null) {
            clinit.instructions = prelude;
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        } else {
            clinit.instructions.insertBefore(first, prelude);
        }
        return true;
    }

    /* -------------------------- crypto helpers ------------------------ */

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 unavailable", e);
        }
    }

    private static byte[] hmacSha256(byte[] data, byte[] key) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new AssertionError("HmacSHA256 unavailable", e);
        }
    }
}
