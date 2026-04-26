package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Randomizes the order of methods and fields inside each class. This is a
 * lightweight cosmetic transform that:
 *
 * <ul>
 *   <li>breaks JAR-diff tools that rely on ordering stability,</li>
 *   <li>forces IDEs to re-sort every class on open, making manual comparison
 *       of an obfuscated build against a source tree tedious,</li>
 *   <li>masks the "first method = important method" heuristic reverse engineers
 *       rely on.</li>
 * </ul>
 *
 * <p>{@code <init>} / {@code <clinit>} are kept at the head so constructor-like
 * logic stays visibly at the top for the JVM itself (no semantic impact either
 * way, but it keeps verification logs tidy).
 */
public class MemberShufflerTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(MemberShufflerTransformer.class);

    @Override
    public String name() {
        return "member-shuffler";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        // Per-class seed mixed with a pool-wide fingerprint. The previous
        // implementation used a global fixed seed (0xBAADF00DL), which made
        // the post-shuffle order across two unrelated JARs share the same
        // permutation pattern -- a weak fingerprint a reverse engineer
        // could exploit. Per-class seeding keeps the order deterministic
        // for a given input (mapping-stable) while removing the global
        // signature.
        long fingerprint = poolFingerprint(pool);
        int classes = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            Random rnd = new Random(fingerprint ^ stableHash(cn.name));
            shuffleMethods(cn, rnd);
            shuffleFields(cn, rnd);
            classes++;
        }
        log.info("Shuffled members in {} classes", classes);
    }

    private static long poolFingerprint(ClassPool pool) {
        long h = 0xCBF29CE484222325L ^ 0xBAADF00DL;
        for (ClassNode cn : pool.allClassNodes()) {
            String n = cn.name;
            for (int i = 0; i < n.length(); i++) {
                h ^= n.charAt(i);
                h *= 0x100000001B3L;
            }
            h ^= 0x5C;
        }
        h = (h ^ (h >>> 30)) * 0xBF58476D1CE4E5B9L;
        h = (h ^ (h >>> 27)) * 0x94D049BB133111EBL;
        h ^= (h >>> 31);
        return h;
    }

    private static long stableHash(String s) {
        long h = 0xCBF29CE484222325L;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i);
            h *= 0x100000001B3L;
        }
        return h;
    }

    private void shuffleMethods(ClassNode cn, Random rnd) {
        if (cn.methods == null || cn.methods.size() < 2) return;
        List<MethodNode> fixed = new ArrayList<>();
        List<MethodNode> movable = new ArrayList<>();
        for (MethodNode mn : cn.methods) {
            if (mn.name.startsWith("<")) fixed.add(mn);
            else movable.add(mn);
        }
        Collections.shuffle(movable, rnd);
        cn.methods.clear();
        cn.methods.addAll(fixed);
        cn.methods.addAll(movable);
    }

    private void shuffleFields(ClassNode cn, Random rnd) {
        if (cn.fields == null || cn.fields.size() < 2) return;
        List<FieldNode> copy = new ArrayList<>(cn.fields);
        Collections.shuffle(copy, rnd);
        cn.fields.clear();
        cn.fields.addAll(copy);
    }
}
