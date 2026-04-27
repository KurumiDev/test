package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import org.objectweb.asm.tree.ClassNode;

import java.util.Map;
import java.util.WeakHashMap;

/**
 * Per-JAR synthetic-name prefix.
 *
 * <p>Every transformer used to bake the literal {@code "$obf"} into the
 * synthetic methods, fields, and helper classes it emitted (e.g.
 * {@code $obfICd<hash>}, {@code $obfBootstrap}, {@code $obfClassVault_<id>}).
 * That made {@code $obf} a free cross-JAR fingerprint -- a single grep
 * across two unrelated obfuscated JARs would surface every synthetic in
 * both, and an LLM-driven reverser could pattern-match the prefix from
 * publicly-available samples of this obfuscator's output.
 *
 * <p>{@link #prefix(ClassPool)} replaces that literal with a deterministic
 * but JAR-specific 6-character prefix (always starts with {@code $} so
 * the resulting name remains a valid Java identifier and is still visibly
 * "private/synthetic" to anyone reading the bytecode). The prefix is
 * derived from the class-pool fingerprint -- the same fingerprint scheme
 * the rest of the obfuscator already uses for seeding -- so two runs of
 * the obfuscator on the same input produce the same prefix (mappings stay
 * stable for retrace) but two different inputs produce different prefixes
 * (cross-JAR fingerprint goes away).
 *
 * <p>Within-JAR all transformers obtain the same prefix because the
 * computation is a pure function of the class pool. We cache the result
 * on the {@link ClassPool} via a {@link WeakHashMap} so the fingerprint
 * is computed once per pool, not once per transformer.
 */
public final class SyntheticNaming {

    private SyntheticNaming() {}

    private static final Map<ClassPool, String> CACHE = new WeakHashMap<>();

    /**
     * Returns the per-JAR 6-character synthetic prefix for {@code pool}.
     * Always starts with {@code '$'} followed by 5 lowercase alphanumeric
     * characters. Stable across runs on the same input pool.
     */
    public static String prefix(ClassPool pool) {
        synchronized (CACHE) {
            String existing = CACHE.get(pool);
            if (existing != null) return existing;
            String computed = computePrefix(pool);
            CACHE.put(pool, computed);
            return computed;
        }
    }

    private static String computePrefix(ClassPool pool) {
        long h = 0xCBF29CE484222325L ^ 0x53D6B17BE5C9CA31L;
        for (ClassNode cn : pool.allClassNodes()) {
            String n = cn.name;
            for (int i = 0; i < n.length(); i++) {
                h ^= n.charAt(i);
                h *= 0x100000001B3L;
            }
            // Mix in the count too, otherwise reordering classes
            // wouldn't perturb the digest of name-suffix sums.
            h ^= 0x9E3779B97F4A7C15L;
        }
        h = (h ^ (h >>> 30)) * 0xBF58476D1CE4E5B9L;
        h = (h ^ (h >>> 27)) * 0x94D049BB133111EBL;
        h ^= (h >>> 31);
        char[] alphabet = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        StringBuilder sb = new StringBuilder("$");
        for (int i = 0; i < 5; i++) {
            int idx = (int) ((h >>> (i * 6)) & 0x3F) % alphabet.length;
            sb.append(alphabet[idx]);
            h = (h ^ (h >>> 7)) * 0xBF58476D1CE4E5B9L;
        }
        return sb.toString();
    }
}
