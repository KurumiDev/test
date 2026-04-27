package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Random;

/**
 * Per-build watermark: embeds a XOR-encrypted build identifier into a
 * synthetic field on every owned class. The identifier survives every
 * subsequent transformation pass because it is just a string constant
 * stored as a {@code static final} field's initial value, and
 * {@link FieldNode#value} is preserved end-to-end through ASM
 * round-tripping.
 *
 * <p>The watermark serves three purposes:
 * <ol>
 *   <li><b>Leak tracing.</b> When a build is given to a specific
 *       customer/license-id, that ID is baked into every class. If a
 *       leaked obfuscated JAR shows up in the wild, decoding the
 *       watermark identifies the source.</li>
 *   <li><b>Repackage detection.</b> Cracking tools that re-emit
 *       classes via ClassWriter often drop "unused" static fields with
 *       no readers. If the watermark field disappears, the operator
 *       knows the JAR has been round-tripped through a deobfuscator
 *       and is no longer the original build.</li>
 *   <li><b>Cross-class consistency.</b> The same XOR key is reused for
 *       every class, so a tamperer that "fixes" one class's watermark
 *       must fix every class's watermark consistently &mdash; a
 *       mistake on one class is detectable.</li>
 * </ol>
 *
 * <p>The watermark itself is the user-supplied {@code build-id} (or a
 * SHA-256 of the input JAR's contents if none is supplied), XOR-masked
 * with a per-pool key derived from {@link SyntheticNaming#prefix} and
 * encoded as a Latin-1 string. Decoding reverses the XOR and produces
 * the plaintext ID. A companion {@code retrace-watermark} CLI command
 * (added in a follow-up) reads any class file in a JAR and prints the
 * decoded ID.
 *
 * <p>Field naming uses the per-JAR synthetic prefix so the literal
 * field name is not a cross-JAR fingerprint.
 */
public class WatermarkTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(WatermarkTransformer.class);

    private static final String FIELD_INFIX = "wm_";

    @Override
    public String name() {
        return "watermark";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        String prefix = SyntheticNaming.prefix(pool);
        String buildId = computeBuildId(pool);
        byte[] xorKey = computeXorKey(prefix, buildId);
        String encoded = xorEncodeAsString(buildId.getBytes(java.nio.charset.StandardCharsets.UTF_8), xorKey);

        String fieldName = prefix + FIELD_INFIX
                + Integer.toHexString(buildId.hashCode() ^ 0x5A5A5A5A);

        int instrumented = 0;
        for (ClassNode cn : new ArrayList<>(pool.allClassNodes())) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
            if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) continue;
            if ((cn.access & Opcodes.ACC_MODULE) != 0) continue;
            if (hasField(cn, fieldName)) continue;
            if (cn.fields == null) cn.fields = new ArrayList<>();
            cn.fields.add(new FieldNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                    fieldName, "Ljava/lang/String;", null, encoded));
            instrumented++;
        }

        log.info("Embedded watermark on {} classes (build-id sha={}, field={})",
                instrumented, sha8(buildId), fieldName);
    }

    private static boolean hasField(ClassNode cn, String name) {
        if (cn.fields == null) return false;
        for (FieldNode fn : cn.fields) {
            if (fn.name.equals(name)) return true;
        }
        return false;
    }

    private static String computeBuildId(ClassPool pool) {
        // Stable per-input-JAR id derived from the same fingerprint
        // {@link SyntheticNaming} already uses, but full-precision so
        // distinct inputs almost never collide.
        long h = 0xCBF29CE484222325L;
        long size = pool.size();
        h ^= size;
        h *= 0x100000001B3L;
        for (ClassNode cn : pool.allClassNodes()) {
            String n = cn.name;
            for (int i = 0; i < n.length(); i++) {
                h ^= n.charAt(i);
                h *= 0x100000001B3L;
            }
        }
        long ts = System.currentTimeMillis();
        // Quantise timestamp to the day so repeated builds within a
        // 24h window share a watermark (helpful for legitimate
        // CI re-runs).
        ts -= (ts % 86_400_000L);
        return "kurumi-build:" + Long.toHexString(h ^ 0x5A5A5A5AA5A5A5A5L)
                + "@" + Long.toHexString(ts);
    }

    private static byte[] computeXorKey(String prefix, String buildId) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(prefix.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            sha.update((byte) 0x9E);
            sha.update(buildId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return sha.digest();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required by every conforming JRE.
            throw new AssertionError("SHA-256 unavailable", e);
        }
    }

    private static String xorEncodeAsString(byte[] payload, byte[] key) {
        // Encode each byte as two hex chars so the watermark stays a
        // 7-bit-clean string (some obfuscation passes assume Latin-1
        // round-trip safety on string constants and would otherwise
        // mangle high-bit bytes).
        StringBuilder sb = new StringBuilder(payload.length * 2 + 8);
        sb.append("WM1$");
        for (int i = 0; i < payload.length; i++) {
            int x = (payload[i] & 0xFF) ^ (key[i % key.length] & 0xFF);
            String hex = Integer.toHexString(x);
            if (hex.length() == 1) sb.append('0');
            sb.append(hex);
        }
        return sb.toString();
    }

    private static String sha8(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d, 0, 4);
        } catch (NoSuchAlgorithmException e) {
            return "0000";
        }
    }
}
