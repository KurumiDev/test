package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.FrameComputingClassWriterFactory;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Dynamic class loading: pulls selected synthetic worker classes out of
 * the JAR entirely and stores their bytecode inside a per-package vault
 * class as an encrypted {@code byte[][]} payload. At class-load time the
 * vault's {@code <clinit>} decrypts each payload and calls
 * {@link java.lang.invoke.MethodHandles.Lookup#defineClass(byte[])} to
 * reinstate the class in the same package.
 *
 * <p>A static reverse engineer looking at the obfuscated JAR will see
 * <em>fewer</em> class files than there are class names referenced in
 * {@code invokedynamic} bootstrap arguments. The missing classes show up
 * as Base64 blobs and an XOR-stream inside one synthetic
 * {@code $obfClassVault_<suffix>} class. Without executing the
 * {@code <clinit>}, tools like CFR, Procyon, or Recaf cannot recover the
 * removed classes &mdash; and the XOR-stream is gated on
 * {@link java.lang.invoke.MethodHandles#lookup()}
 * {@code .lookupClass().getName().hashCode()}, so extracting the stream
 * into another tool with a different class name yields garbage bytes.
 *
 * <p>Only class-exploder workers are eligible. They have no external
 * references from outside the pool (they are wired in via opaque
 * predicates that the indy-call transformer has already rewritten into
 * invokedynamic). A fraction is chosen pseudo-randomly; the remainder
 * stay in the JAR so a purely structural static-analysis tool that
 * expects some normal class shapes is not tipped off that every
 * "LicenseGuard_*" has vanished.
 *
 * <p>The transformer runs <b>last</b> so it encrypts the final,
 * fully-obfuscated bytecode of each worker &mdash; blob-encrypted
 * strings, indy-wrapped calls, polymorphic decoders and all. Each vault
 * is placed in the same package as the classes it holds so
 * {@code Lookup.defineClass} succeeds under its same-package
 * restriction. Every surviving class in a package whose workers were
 * moved gains a one-line {@code Class.forName(vaultName)} prefix to its
 * {@code <clinit>}, guaranteeing the vault's initializer runs before any
 * encrypted worker is referenced.
 */
public class EncryptedClassVaultTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(EncryptedClassVaultTransformer.class);

    private static final String VAULT_INFIX = "ClassVault_";
    private static final String LOAD_SUFFIX = "Load";
    private static final String DECRYPT_SUFFIX = "Decrypt";
    private static final int VAULT_SEED = 0x5B19DCE5;

    // Worker class-name prefixes emitted by {@link ClassExploderTransformer}.
    // Only classes whose simple name starts with one of these followed by
    // an underscore are considered for encryption. Other classes (renamed
    // originals like {@code o/a}, the main plugin class, etc.) are left
    // untouched.
    private static final Set<String> WORKER_ROOTS = new HashSet<>(Arrays.asList(
            "LicenseGuard", "AuthProbe", "HeartbeatSink", "TokenRing",
            "SignatureMatcher", "UpdateFetcher", "IntegrityAudit",
            "TelemetryBeacon", "SessionRefresher", "HwidResolver",
            "EndpointProbe", "ApiKeyRotator", "AccessAuditor",
            "CertPinner", "NonceMint", "ReplayShield"
    ));

    /**
     * Encrypt at most this fraction of eligible workers per package.
     * We deliberately leave some workers behind so a static analyzer
     * does not get a clean signal that every "LicenseGuard_*" disappeared.
     */
    private static final double ENCRYPT_FRACTION = 0.5;

    @Override
    public String name() {
        return "encrypted-class-vault";
    }

    @Override
    public boolean isEnabled(dev.kurumi.obfuscator.config.ObfuscatorConfig config) {
        return config.isTransformerEnabled("encrypted-class-vault");
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        final String pfx = SyntheticNaming.prefix(pool);
        final String vaultPrefix = pfx + VAULT_INFIX;
        final String loadName = pfx + LOAD_SUFFIX;
        final String decryptName = pfx + DECRYPT_SUFFIX;
        Map<String, List<ClassNode>> byPackage = new LinkedHashMap<>();
        for (ClassNode cn : pool.allClassNodes()) {
            if (!isEncryptableWorker(cn.name)) continue;
            String pkg = packageOf(cn.name);
            byPackage.computeIfAbsent(pkg, k -> new ArrayList<>()).add(cn);
        }

        if (byPackage.isEmpty()) {
            log.info("No eligible workers to encrypt");
            return;
        }

        FrameComputingClassWriterFactory writerFactory = new FrameComputingClassWriterFactory(pool);

        int totalEncrypted = 0;
        int vaults = 0;
        for (Map.Entry<String, List<ClassNode>> entry : byPackage.entrySet()) {
            String pkg = entry.getKey();
            List<ClassNode> candidates = entry.getValue();
            // Deterministic selection per package so repeated runs
            // produce the same vault contents.
            Random rnd = new Random(stableSeed(pkg));
            int toEncrypt = Math.max(1, (int) Math.round(candidates.size() * ENCRYPT_FRACTION));
            java.util.Collections.shuffle(candidates, rnd);
            List<ClassNode> selected = candidates.subList(0, Math.min(toEncrypt, candidates.size()));

            String vaultInternal = pkg.isEmpty()
                    ? vaultPrefix + packageSuffix(pkg)
                    : pkg + "/" + vaultPrefix + packageSuffix(pkg);
            // All payloads in a single vault share the vault's variant; the
            // vault's {@code <clinit>} only has one decoder body, so
            // per-worker variants would need a per-worker dispatch table.
            int vaultVariant = DecoderPolymorphism.variantFor(vaultInternal);
            int identityHash = vaultInternal.replace('/', '.').hashCode();

            List<byte[]> encryptedPayloads = new ArrayList<>(selected.size());
            int[] seeds = new int[selected.size()];
            for (int i = 0; i < selected.size(); i++) {
                ClassNode worker = selected.get(i);
                byte[] plain = writerFactory.toBytes(worker);
                int litSeed = stableSeed(worker.name) & 0x7FFFFFFF;
                int effective = litSeed ^ identityHash;
                byte[] enc = DecoderPolymorphism.xorByteStream(plain, effective, vaultVariant);
                encryptedPayloads.add(enc);
                seeds[i] = litSeed;
                pool.removeClass(worker.name);
                totalEncrypted++;
            }

            ClassNode vault = buildVault(pool, vaultInternal, encryptedPayloads, seeds, selected,
                    loadName, decryptName);
            pool.addClass(vault);
            vaults++;

            injectVaultReference(pool, pkg, vaultInternal, vault.name, selected);
        }

        log.info("Moved {} workers into {} encrypted vault(s)",
                totalEncrypted, vaults);
    }

    private static boolean isEncryptableWorker(String internalName) {
        String simple = simpleName(internalName);
        int underscore = simple.indexOf('_');
        if (underscore <= 0) return false;
        String root = simple.substring(0, underscore);
        return WORKER_ROOTS.contains(root);
    }

    private static String simpleName(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return (slash < 0) ? internalName : internalName.substring(slash + 1);
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return (slash < 0) ? "" : internalName.substring(0, slash);
    }

    private static int stableSeed(String s) {
        int h = 0x9E3779B1;
        for (int i = 0; i < s.length(); i++) {
            h = h * 31 + s.charAt(i);
            h ^= (h >>> 16);
        }
        return h | 1;
    }

    private static String packageSuffix(String pkg) {
        long h = 0xCBF29CE484222325L;
        for (int i = 0; i < pkg.length(); i++) {
            h ^= pkg.charAt(i);
            h *= 0x100000001B3L;
        }
        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        char[] out = new char[8];
        for (int i = 0; i < out.length; i++) {
            out[i] = alphabet[(int) ((h >>> (i * 8)) & 0x3F) % alphabet.length];
            h = (h ^ (h >>> 7)) * 0xBF58476D1CE4E5B9L;
        }
        return new String(out);
    }

    /**
     * Builds a vault class whose {@code <clinit>} reads {@code N} encrypted
     * payloads from embedded resource files {@code
     * META-INF/obf/<vaultName>/<i>.bin}, decrypts them with the per-package
     * polymorphic cipher variant, and calls
     * {@link java.lang.invoke.MethodHandles.Lookup#defineClass(byte[])} on
     * each resulting byte array. The resources are added to the pool's
     * {@code resources()} map; payload literals do <em>not</em> live in the
     * vault's constant pool (which would quickly bust the 65&nbsp;535-byte
     * method-size limit for {@code <clinit>}).
     */
    private ClassNode buildVault(ClassPool pool, String vaultInternal,
                                 List<byte[]> encryptedPayloads,
                                 int[] seeds, List<ClassNode> selected,
                                 String loadName, String decryptName) {
        ClassNode vault = new ClassNode();
        vault.version = Opcodes.V17;
        vault.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        vault.name = vaultInternal;
        vault.superName = "java/lang/Object";

        MethodNode init = new MethodNode(0, "<init>", "()V", null, null);
        InsnList ictor = init.instructions;
        ictor.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ictor.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ictor.add(new InsnNode(Opcodes.RETURN));
        init.maxLocals = 1;
        init.maxStack = 1;
        vault.methods.add(init);

        int n = encryptedPayloads.size();
        int variant = DecoderPolymorphism.variantFor(vaultInternal);

        String resourcePrefix = "META-INF/obf/" + vaultInternal + "/";
        for (int i = 0; i < n; i++) {
            pool.resources().put(resourcePrefix + i + ".bin", encryptedPayloads.get(i));
        }

        vault.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                "SEEDS", "[I", null, null));

        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList cl = clinit.instructions;

        // SEEDS = new int[n] { seeds[0], seeds[1], ... }
        loadInt(cl, n);
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        for (int i = 0; i < n; i++) {
            cl.add(new InsnNode(Opcodes.DUP));
            loadInt(cl, i);
            cl.add(new LdcInsnNode(Integer.valueOf(seeds[i])));
            cl.add(new InsnNode(Opcodes.IASTORE));
        }
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, vault.name, "SEEDS", "[I"));

        // Lookup lookup = MethodHandles.lookup();
        cl.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/invoke/MethodHandles", "lookup",
                "()Ljava/lang/invoke/MethodHandles$Lookup;", false));
        cl.add(new VarInsnNode(Opcodes.ASTORE, 0));

        // int identityHash = lookup.lookupClass().getName().hashCode();
        cl.add(new VarInsnNode(Opcodes.ALOAD, 0));
        cl.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", "lookupClass",
                "()Ljava/lang/Class;", false));
        cl.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Class", "getName", "()Ljava/lang/String;", false));
        cl.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/String", "hashCode", "()I", false));
        cl.add(new VarInsnNode(Opcodes.ISTORE, 1));

        // ClassLoader loader = lookup.lookupClass().getClassLoader();
        cl.add(new VarInsnNode(Opcodes.ALOAD, 0));
        cl.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", "lookupClass",
                "()Ljava/lang/Class;", false));
        cl.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Class", "getClassLoader",
                "()Ljava/lang/ClassLoader;", false));
        cl.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // int i = 0;
        cl.add(new InsnNode(Opcodes.ICONST_0));
        cl.add(new VarInsnNode(Opcodes.ISTORE, 3));

        LabelNode loop = new LabelNode();
        LabelNode loopEnd = new LabelNode();
        cl.add(loop);
        cl.add(new VarInsnNode(Opcodes.ILOAD, 3));
        loadInt(cl, n);
        cl.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // effSeed = SEEDS[i] ^ identityHash
        cl.add(new FieldInsnNode(Opcodes.GETSTATIC, vault.name, "SEEDS", "[I"));
        cl.add(new VarInsnNode(Opcodes.ILOAD, 3));
        cl.add(new InsnNode(Opcodes.IALOAD));
        cl.add(new VarInsnNode(Opcodes.ILOAD, 1));
        cl.add(new InsnNode(Opcodes.IXOR));
        cl.add(new VarInsnNode(Opcodes.ISTORE, 4));

        // byte[] enc = ${loadName}(loader, i)
        cl.add(new VarInsnNode(Opcodes.ALOAD, 2));
        cl.add(new VarInsnNode(Opcodes.ILOAD, 3));
        cl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, vault.name,
                loadName, "(Ljava/lang/ClassLoader;I)[B", false));
        cl.add(new VarInsnNode(Opcodes.ASTORE, 5));

        // byte[] plain = ${decryptName}(enc, effSeed)
        cl.add(new VarInsnNode(Opcodes.ALOAD, 5));
        cl.add(new VarInsnNode(Opcodes.ILOAD, 4));
        cl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, vault.name,
                decryptName, "([BI)[B", false));
        cl.add(new VarInsnNode(Opcodes.ASTORE, 6));

        // lookup.defineClass(plain)
        cl.add(new VarInsnNode(Opcodes.ALOAD, 0));
        cl.add(new VarInsnNode(Opcodes.ALOAD, 6));
        cl.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", "defineClass",
                "([B)Ljava/lang/Class;", false));
        cl.add(new InsnNode(Opcodes.POP));

        cl.add(new IincInsnNode(3, 1));
        cl.add(new JumpInsnNode(Opcodes.GOTO, loop));
        cl.add(loopEnd);

        cl.add(new InsnNode(Opcodes.RETURN));

        clinit.maxLocals = 7;
        clinit.maxStack = 6;
        vault.methods.add(clinit);

        vault.methods.add(buildLoad(resourcePrefix, loadName));
        vault.methods.add(buildDecrypt(variant, decryptName));
        return vault;
    }

    /**
     * private static synthetic byte[] $obfLoad(ClassLoader cl, int idx) throws IOException {
     *   java.io.InputStream in = cl.getResourceAsStream(PREFIX + idx + ".bin");
     *   java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
     *   byte[] buf = new byte[4096];
     *   int r;
     *   while ((r = in.read(buf)) &gt; 0) out.write(buf, 0, r);
     *   in.close();
     *   return out.toByteArray();
     * }
     */
    private MethodNode buildLoad(String resourcePrefix, String loadName) {
        MethodNode m = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                loadName, "(Ljava/lang/ClassLoader;I)[B",
                null, new String[]{"java/io/IOException"});
        InsnList il = m.instructions;
        // slots: 0=cl, 1=idx, 2=in, 3=out, 4=buf, 5=r

        // String resName = PREFIX + idx + ".bin";  -> via StringBuilder
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/StringBuilder", "<init>", "()V", false));
        il.add(new LdcInsnNode(resourcePrefix));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        il.add(new VarInsnNode(Opcodes.ILOAD, 1));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append",
                "(I)Ljava/lang/StringBuilder;", false));
        il.add(new LdcInsnNode(".bin"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "toString",
                "()Ljava/lang/String;", false));

        // in = cl.getResourceAsStream(resName)
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new InsnNode(Opcodes.SWAP));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/ClassLoader", "getResourceAsStream",
                "(Ljava/lang/String;)Ljava/io/InputStream;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // out = new ByteArrayOutputStream()
        il.add(new TypeInsnNode(Opcodes.NEW, "java/io/ByteArrayOutputStream"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/io/ByteArrayOutputStream", "<init>", "()V", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 3));

        // buf = new byte[4096]
        il.add(new IntInsnNode(Opcodes.SIPUSH, 4096));
        il.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        il.add(new VarInsnNode(Opcodes.ASTORE, 4));

        // while ((r = in.read(buf)) > 0) out.write(buf, 0, r)
        LabelNode loop = new LabelNode();
        LabelNode loopEnd = new LabelNode();
        il.add(loop);
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/io/InputStream", "read", "([B)I", false));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ISTORE, 5));
        il.add(new JumpInsnNode(Opcodes.IFLE, loopEnd));
        il.add(new VarInsnNode(Opcodes.ALOAD, 3));
        il.add(new VarInsnNode(Opcodes.ALOAD, 4));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ILOAD, 5));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/io/ByteArrayOutputStream", "write", "([BII)V", false));
        il.add(new JumpInsnNode(Opcodes.GOTO, loop));
        il.add(loopEnd);

        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/io/InputStream", "close", "()V", false));

        il.add(new VarInsnNode(Opcodes.ALOAD, 3));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/io/ByteArrayOutputStream", "toByteArray", "()[B", false));
        il.add(new InsnNode(Opcodes.ARETURN));

        m.maxLocals = 6;
        m.maxStack = 4;
        return m;
    }

    /**
     * private static synthetic byte[] $obfDecrypt(byte[] enc, int key) {
     *   byte[] out = new byte[enc.length];
     *   int k = key;
     *   for (int i = 0; i < enc.length; i++) {
     *     int plain = (enc[i] &amp; 0xFF) ^ mask(k, i, variant);
     *     out[i] = (byte) plain;
     *     keyUpdate(k, i, plain, variant);
     *   }
     *   return out;
     * }
     */
    private MethodNode buildDecrypt(int variant, String decryptName) {
        MethodNode m = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                decryptName, "([BI)[B", null, null);
        InsnList il = m.instructions;
        // slots: 0=enc, 1=k, 2=out, 3=i, 4=plain
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));

        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));

        LabelNode loop = new LabelNode();
        LabelNode loopEnd = new LabelNode();
        il.add(loop);
        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // plain = (enc[i] & 0xFF) ^ mask
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new InsnNode(Opcodes.BALOAD));
        il.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
        il.add(new InsnNode(Opcodes.IAND));
        DecoderPolymorphism.emitMask(il, 1, 3, variant);
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new VarInsnNode(Opcodes.ISTORE, 4));

        // out[i] = (byte) plain
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new InsnNode(Opcodes.I2B));
        il.add(new InsnNode(Opcodes.BASTORE));

        DecoderPolymorphism.emitKeyUpdate(il, 1, 3, 4, variant);

        il.add(new IincInsnNode(3, 1));
        il.add(new JumpInsnNode(Opcodes.GOTO, loop));
        il.add(loopEnd);

        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new InsnNode(Opcodes.ARETURN));

        m.maxLocals = 5;
        m.maxStack = 5;
        return m;
    }

    /**
     * Prefix the {@code <clinit>} of every class in the vault's package
     * (except the vault itself) with a {@code Class.forName(vaultFqn)} so
     * the vault initializer runs before any encrypted worker is first
     * referenced.
     */
    private void injectVaultReference(ClassPool pool, String pkg,
                                      String vaultInternal, String vaultName,
                                      List<ClassNode> removed) {
        Set<String> removedNames = new HashSet<>();
        for (ClassNode r : removed) removedNames.add(r.name);
        String fqn = vaultName.replace('/', '.');

        for (ClassNode cn : pool.allClassNodes()) {
            if (cn.name.equals(vaultName)) continue;
            if (!packageOf(cn.name).equals(pkg)) continue;
            if (removedNames.contains(cn.name)) continue;
            // Interfaces/annotations: skip. Adding a <clinit> to them is
            // legal but risks the interface being re-initialized out of
            // sequence on some older JVMs.
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
            if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) continue;
            prefixClinit(cn, fqn);
        }
    }

    private void prefixClinit(ClassNode cn, String vaultFqn) {
        MethodNode clinit = null;
        for (MethodNode m : cn.methods) {
            if ("<clinit>".equals(m.name) && "()V".equals(m.desc)) {
                clinit = m;
                break;
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            clinit.maxLocals = 0;
            clinit.maxStack = 1;
            cn.methods.add(clinit);
        }

        InsnList prefix = new InsnList();
        // Class.forName(vaultFqn)  // triggers vault <clinit>
        prefix.add(new LdcInsnNode(vaultFqn));
        prefix.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false));
        prefix.add(new InsnNode(Opcodes.POP));

        // Wrap in try/catch (Throwable) so a missing vault (e.g. when
        // someone loads this class in a tool outside Paper's classloader
        // context) does not silently break <clinit>.
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode after = new LabelNode();

        InsnList wrapped = new InsnList();
        wrapped.add(start);
        wrapped.add(prefix);
        wrapped.add(end);
        wrapped.add(new JumpInsnNode(Opcodes.GOTO, after));
        wrapped.add(handler);
        wrapped.add(new InsnNode(Opcodes.POP));
        wrapped.add(after);

        clinit.instructions.insert(wrapped);
        if (clinit.tryCatchBlocks == null) {
            clinit.tryCatchBlocks = new ArrayList<>();
        }
        clinit.tryCatchBlocks.add(0, new org.objectweb.asm.tree.TryCatchBlockNode(
                start, end, handler, "java/lang/Throwable"));
        // maxStack must accommodate LDC + INVOKESTATIC (1-arg static).
        clinit.maxStack = Math.max(clinit.maxStack, 2);
    }

    private static void loadInt(InsnList il, int v) {
        if (v >= -1 && v <= 5) {
            il.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            il.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            il.add(new IntInsnNode(Opcodes.SIPUSH, v));
        } else {
            il.add(new LdcInsnNode(Integer.valueOf(v)));
        }
    }
}
