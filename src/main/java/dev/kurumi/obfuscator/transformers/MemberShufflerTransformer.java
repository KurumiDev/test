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
        Random rnd = new Random(0xBAADF00DL);
        int classes = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            shuffleMethods(cn, rnd);
            shuffleFields(cn, rnd);
            classes++;
        }
        log.info("Shuffled members in {} classes", classes);
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
