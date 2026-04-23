package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Packs every distinct LDC string literal in a class into a single encrypted
 * byte[] blob and rewrites every usage into a {@code $obfBS(int)} call that
 * lazily materializes the string from the blob on first access.
 *
 * <p>Compared to {@link StringEncryptionTransformer}, which replaces each
 * LDC with a self-contained {@code $obfD(base64)} call, BlobString
 * centralizes all strings of a class into one opaque binary blob with a
 * position-dependent key schedule. A reverse engineer can no longer grep
 * for individual Base64 literals to recover the table — they have to
 * execute or emulate the decoder and know the index mapping.
 *
 * <p>Runs <b>before</b> {@link StringEncryptionTransformer} in the pipeline.
 * If both are enabled, strings handled here do not re-enter StringEncryption
 * because they are no longer LDC string constants after this pass.
 */
public class BlobStringTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(BlobStringTransformer.class);

    // Per-class randomized decoder/field names. A reverse engineer can no
    // longer grep for a fixed symbol like `$obfBS` to find every decoder in
    // the JAR — each class gets its own 8-char suffix derived
    // deterministically from the class name.
    //
    // Layout: ${PREFIX}${suffix}b  — byte[] blob
    //         ${PREFIX}${suffix}o  — int[] offsets
    //         ${PREFIX}${suffix}c  — String[] lazy cache
    //         ${PREFIX}${suffix}   — static String decoder(int)
    private static final String PREFIX = "$obf";

    @Override
    public String name() {
        return "blob-string";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int totalStrings = 0;
        int classesTouched = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ("module-info".equals(cn.name)) continue;
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
            if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) continue;
            int n = rewriteOne(cn);
            if (n > 0) {
                totalStrings += n;
                classesTouched++;
            }
        }
        if (totalStrings > 0) {
            log.info("Packed {} strings into per-class blobs across {} classes",
                    totalStrings, classesTouched);
        } else {
            log.info("No strings to pack");
        }
    }

    private int rewriteOne(ClassNode cn) {
        String suffix = randomSuffix(cn.name);
        String blobField = PREFIX + suffix + "b";
        String offsetsField = PREFIX + suffix + "o";
        String cacheField = PREFIX + suffix + "c";
        String decoder = PREFIX + suffix;

        // Phase 1: collect all distinct LDC string constants.
        LinkedHashMap<String, Integer> indexByString = new LinkedHashMap<>();
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (decoder.equals(mn.name)) continue;
            for (AbstractInsnNode insn : mn.instructions.toArray()) {
                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    indexByString.computeIfAbsent(s, k -> indexByString.size());
                }
            }
        }
        if (indexByString.isEmpty()) return 0;

        // Phase 2: build blob + offsets table. The blob holds all UTF-8 bytes
        // concatenated; offsets[i] gives the byte-offset of string i, and
        // offsets[n] is total length so that strings[i] = blob[offsets[i]..offsets[i+1]).
        int count = indexByString.size();
        int[] offsets = new int[count + 1];
        byte[][] encodedStrings = new byte[count][];
        int total = 0;
        int i = 0;
        for (String s : indexByString.keySet()) {
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            encodedStrings[i] = bytes;
            offsets[i] = total;
            total += bytes.length;
            i++;
        }
        offsets[count] = total;

        // Concatenate raw bytes then encrypt with position-dependent LCG key.
        byte[] raw = new byte[total];
        int p = 0;
        for (byte[] bs : encodedStrings) {
            System.arraycopy(bs, 0, raw, p, bs.length);
            p += bs.length;
        }
        int seed = seedFor(cn.name);
        byte[] enc = encrypt(raw, seed);
        String encB64 = Base64.getEncoder().encodeToString(enc);

        // Phase 3: inject fields.
        if (!hasField(cn, blobField)) {
            cn.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                    blobField, "[B", null, null));
        }
        if (!hasField(cn, offsetsField)) {
            cn.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                    offsetsField, "[I", null, null));
        }
        if (!hasField(cn, cacheField)) {
            cn.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    cacheField, "[Ljava/lang/String;", null, null));
        }

        // Phase 4: inject <clinit> prefix to initialize blob + offsets.
        injectClinitPrefix(cn, encB64, offsets, seed, blobField, offsetsField, cacheField);

        // Phase 5: inject decoder method.
        if (!hasMethod(cn, decoder, "(I)Ljava/lang/String;")) {
            cn.methods.add(buildDecoder(cn, decoder, blobField, offsetsField, cacheField));
        }

        // Phase 6: rewrite each LDC to INVOKESTATIC cn.decoder(I)String.
        Map<String, Integer> fixedIndex = new HashMap<>(indexByString);
        int replaced = 0;
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            if (decoder.equals(mn.name)) continue;
            if ("<clinit>".equals(mn.name)) continue;
            for (AbstractInsnNode insn : mn.instructions.toArray()) {
                if (!(insn instanceof LdcInsnNode ldc)) continue;
                if (!(ldc.cst instanceof String s)) continue;
                Integer idx = fixedIndex.get(s);
                if (idx == null) continue;
                InsnList repl = new InsnList();
                repl.add(loadInt(idx));
                repl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decoder,
                        "(I)Ljava/lang/String;", false));
                mn.instructions.insert(insn, repl);
                mn.instructions.remove(insn);
                replaced++;
            }
        }
        return replaced;
    }

    /**
     * Derives a stable 8-character alphanumeric suffix from the class name.
     * Two classes in the same JAR get different suffixes (as long as their
     * internal names differ), but the same class always gets the same
     * suffix, which is important for deterministic diffs and reproducible
     * builds.
     */
    private static String randomSuffix(String className) {
        long h = 0xCBF29CE484222325L;
        for (int i = 0; i < className.length(); i++) {
            h ^= className.charAt(i);
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

    private static int seedFor(String className) {
        int h = 0x9E3779B1;
        for (int i = 0; i < className.length(); i++) {
            h = h * 31 + className.charAt(i);
            h ^= (h >>> 16);
        }
        return h | 1;
    }

    private static byte[] encrypt(byte[] raw, int seed) {
        byte[] out = new byte[raw.length];
        int k = seed;
        for (int i = 0; i < raw.length; i++) {
            out[i] = (byte) (raw[i] ^ ((k ^ (i * 0x9E3779B9)) & 0xFF));
            k = k * 0x45D9F3B + 0x119DE1F3;
        }
        return out;
    }

    private static AbstractInsnNode loadInt(int v) {
        if (v >= -1 && v <= 5) {
            return new InsnNode(Opcodes.ICONST_0 + v);
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            return new IntInsnNode(Opcodes.BIPUSH, v);
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            return new IntInsnNode(Opcodes.SIPUSH, v);
        } else {
            return new LdcInsnNode(Integer.valueOf(v));
        }
    }

    private static boolean hasField(ClassNode cn, String name) {
        for (FieldNode f : cn.fields) if (f.name.equals(name)) return true;
        return false;
    }

    private static boolean hasMethod(ClassNode cn, String name, String desc) {
        for (MethodNode m : cn.methods) if (m.name.equals(name) && m.desc.equals(desc)) return true;
        return false;
    }

    /**
     * Prepends bytecode to {@code <clinit>} that decodes the Base64 blob,
     * XOR-decrypts it, stores the plaintext bytes in {@link #BLOB_FIELD} and
     * writes the offsets table into {@link #OFFSETS_FIELD}. Creates
     * {@code <clinit>} if the class doesn't already have one.
     */
    private void injectClinitPrefix(ClassNode cn, String encB64, int[] offsets, int seed,
                                    String blobField, String offsetsField, String cacheField) {
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
            cn.methods.add(clinit);
        }

        InsnList prefix = new InsnList();

        // byte[] raw = Base64.getDecoder().decode(encB64);
        prefix.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64",
                "getDecoder", "()Ljava/util/Base64$Decoder;", false));
        prefix.add(new LdcInsnNode(encB64));
        prefix.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder",
                "decode", "(Ljava/lang/String;)[B", false));
        // Stack: [raw]

        // int len = raw.length
        prefix.add(new InsnNode(Opcodes.DUP));
        prefix.add(new InsnNode(Opcodes.ARRAYLENGTH));
        // Stack: [raw, len]

        // byte[] out = new byte[len]
        prefix.add(new InsnNode(Opcodes.DUP));
        prefix.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        // Stack: [raw, len, out]

        // XOR loop: for i in 0..len { out[i] = raw[i] ^ ((k ^ (i * 0x9E3779B9)) & 0xFF); k = k*...+...; }
        // We use locals: 0=raw, 1=len, 2=out, 3=k, 4=i (local reservation)
        int Lraw = clinit.maxLocals + 0;
        int Lout = clinit.maxLocals + 1;
        int Lk = clinit.maxLocals + 2;
        int Li = clinit.maxLocals + 3;
        int Llen = clinit.maxLocals + 4;

        prefix.add(new VarInsnNode(Opcodes.ASTORE, Lout));   // out
        prefix.add(new VarInsnNode(Opcodes.ISTORE, Llen));   // len
        prefix.add(new VarInsnNode(Opcodes.ASTORE, Lraw));   // raw
        prefix.add(new LdcInsnNode(Integer.valueOf(seed)));
        prefix.add(new VarInsnNode(Opcodes.ISTORE, Lk));
        prefix.add(new InsnNode(Opcodes.ICONST_0));
        prefix.add(new VarInsnNode(Opcodes.ISTORE, Li));

        LabelNode loop = new LabelNode();
        LabelNode loopEnd = new LabelNode();
        prefix.add(loop);
        prefix.add(new VarInsnNode(Opcodes.ILOAD, Li));
        prefix.add(new VarInsnNode(Opcodes.ILOAD, Llen));
        prefix.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // out[i] = raw[i] ^ ((k ^ (i * MUL)) & 0xFF)
        prefix.add(new VarInsnNode(Opcodes.ALOAD, Lout));
        prefix.add(new VarInsnNode(Opcodes.ILOAD, Li));
        prefix.add(new VarInsnNode(Opcodes.ALOAD, Lraw));
        prefix.add(new VarInsnNode(Opcodes.ILOAD, Li));
        prefix.add(new InsnNode(Opcodes.BALOAD));
        // stack: raw[i] (int, sign-extended)
        prefix.add(new VarInsnNode(Opcodes.ILOAD, Lk));
        prefix.add(new VarInsnNode(Opcodes.ILOAD, Li));
        prefix.add(new LdcInsnNode(Integer.valueOf(0x9E3779B9)));
        prefix.add(new InsnNode(Opcodes.IMUL));
        prefix.add(new InsnNode(Opcodes.IXOR));
        prefix.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
        prefix.add(new InsnNode(Opcodes.IAND));
        // stack: raw[i], maskedK
        prefix.add(new InsnNode(Opcodes.IXOR));
        prefix.add(new InsnNode(Opcodes.I2B));
        prefix.add(new InsnNode(Opcodes.BASTORE));

        // k = k * 0x45D9F3B + 0x119DE1F3
        prefix.add(new VarInsnNode(Opcodes.ILOAD, Lk));
        prefix.add(new LdcInsnNode(Integer.valueOf(0x45D9F3B)));
        prefix.add(new InsnNode(Opcodes.IMUL));
        prefix.add(new LdcInsnNode(Integer.valueOf(0x119DE1F3)));
        prefix.add(new InsnNode(Opcodes.IADD));
        prefix.add(new VarInsnNode(Opcodes.ISTORE, Lk));

        prefix.add(new IincInsnNode(Li, 1));
        prefix.add(new JumpInsnNode(Opcodes.GOTO, loop));
        prefix.add(loopEnd);

        // blobField = out
        prefix.add(new VarInsnNode(Opcodes.ALOAD, Lout));
        prefix.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, blobField, "[B"));

        // offsetsField = new int[]{offsets...}
        prefix.add(loadInt(offsets.length));
        prefix.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        for (int k = 0; k < offsets.length; k++) {
            prefix.add(new InsnNode(Opcodes.DUP));
            prefix.add(loadInt(k));
            prefix.add(loadInt(offsets[k]));
            prefix.add(new InsnNode(Opcodes.IASTORE));
        }
        prefix.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, offsetsField, "[I"));

        // cacheField = new String[count]
        prefix.add(loadInt(offsets.length - 1));
        prefix.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
        prefix.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, cacheField,
                "[Ljava/lang/String;"));

        clinit.instructions.insert(prefix);
        clinit.maxLocals = Math.max(clinit.maxLocals, Llen + 1);
        clinit.maxStack = Math.max(clinit.maxStack, 6);
    }

    /**
     * Decoder method: returns the i-th string from the per-class blob,
     * lazily materializing it on first access and caching in
     * {@link #CACHE_FIELD}.
     *
     * <pre>
     * private static synthetic String $obfBS(int idx) {
     *   String[] cache = $obfBSc;
     *   String cached = cache[idx];
     *   if (cached != null) return cached;
     *   int start = $obfBSo[idx];
     *   int end = $obfBSo[idx + 1];
     *   byte[] blob = $obfBSb;
     *   byte[] slice = new byte[end - start];
     *   System.arraycopy(blob, start, slice, 0, end - start);
     *   String out = new String(slice, StandardCharsets.UTF_8);
     *   cache[idx] = out;
     *   return out;
     * }
     * </pre>
     */
    private MethodNode buildDecoder(ClassNode cn, String decoder, String blobField,
                                    String offsetsField, String cacheField) {
        MethodNode m = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                decoder, "(I)Ljava/lang/String;", null, null);

        // Locals: 0=idx, 1=cache, 2=cached, 3=start, 4=end, 5=slice
        InsnList il = m.instructions;

        // cache = cacheField
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, cacheField,
                "[Ljava/lang/String;"));
        il.add(new VarInsnNode(Opcodes.ASTORE, 1));

        // cached = cache[idx]
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new InsnNode(Opcodes.AALOAD));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // if (cached != null) return cached
        LabelNode notCached = new LabelNode();
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new JumpInsnNode(Opcodes.IFNULL, notCached));
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new InsnNode(Opcodes.ARETURN));

        il.add(notCached);

        // start = offsetsField[idx]
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, offsetsField, "[I"));
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new InsnNode(Opcodes.IALOAD));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));

        // end = offsetsField[idx + 1]
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, offsetsField, "[I"));
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new InsnNode(Opcodes.IALOAD));
        il.add(new VarInsnNode(Opcodes.ISTORE, 4));

        // slice = new byte[end - start]
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new InsnNode(Opcodes.ISUB));
        il.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        il.add(new VarInsnNode(Opcodes.ASTORE, 5));

        // System.arraycopy(blobField, start, slice, 0, end - start)
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, blobField, "[B"));
        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new VarInsnNode(Opcodes.ALOAD, 5));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new InsnNode(Opcodes.ISUB));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System",
                "arraycopy",
                "(Ljava/lang/Object;ILjava/lang/Object;II)V", false));

        // out = new String(slice, StandardCharsets.UTF_8)
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, 5));
        il.add(new FieldInsnNode(Opcodes.GETSTATIC,
                "java/nio/charset/StandardCharsets", "UTF_8",
                "Ljava/nio/charset/Charset;"));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String",
                "<init>", "([BLjava/nio/charset/Charset;)V", false));

        // cache[idx] = out;  return out
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new InsnNode(Opcodes.SWAP));
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new InsnNode(Opcodes.SWAP));
        il.add(new InsnNode(Opcodes.AASTORE));
        il.add(new InsnNode(Opcodes.ARETURN));

        m.maxLocals = 6;
        m.maxStack = 6;
        return m;
    }
}
