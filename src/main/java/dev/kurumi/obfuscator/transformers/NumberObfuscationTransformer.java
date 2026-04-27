package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Replaces numeric constants with arithmetic / bitwise equivalents. By default
 * only touches "magic numbers" (abs value > 10) so loop counters stay readable
 * at no cost.
 */
public class NumberObfuscationTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(NumberObfuscationTransformer.class);

    @Override
    public String name() {
        return "number-obfuscation";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        boolean onlyMagic = ctx.config().numberOnlyMagic();
        int depth = ctx.config().numberDepth();
        int replaced = 0;
        // Per-JAR synthetic prefix: skip our own emitted synthetics so we
        // don't, e.g., obfuscate the magic constants baked into the
        // string-decoder LCG step. Earlier versions hard-coded "$obf"
        // here; that left a single literal in the codebase pointing at
        // the obfuscator's own synthetic naming convention.
        final String pfx = SyntheticNaming.prefix(pool);
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith(pfx)) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    Integer iv = intConstant(insn);
                    if (iv != null) {
                        if (onlyMagic && isTrivialInt(iv)) continue;
                        InsnList rep = obfInt(iv, depth);
                        mn.instructions.insert(insn, rep);
                        mn.instructions.remove(insn);
                        replaced++;
                        continue;
                    }
                    Long lv = longConstant(insn);
                    if (lv != null) {
                        if (onlyMagic && isTrivialLong(lv)) continue;
                        InsnList rep = obfLong(lv, depth);
                        mn.instructions.insert(insn, rep);
                        mn.instructions.remove(insn);
                        replaced++;
                    }
                }
            }
        }
        log.info("Obfuscated {} numeric constants (depth={})", replaced, depth);
    }

    private Integer intConstant(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) return op - Opcodes.ICONST_0;
        if (insn instanceof IntInsnNode i && (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH)) return i.operand;
        if (insn instanceof LdcInsnNode l && l.cst instanceof Integer i) return i;
        return null;
    }

    private Long longConstant(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (op == Opcodes.LCONST_0) return 0L;
        if (op == Opcodes.LCONST_1) return 1L;
        if (insn instanceof LdcInsnNode l && l.cst instanceof Long lv) return lv;
        return null;
    }

    // Keep tiny constants readable: -1, 0, 1, 2 are almost always loop counters / sentinels.
    private static boolean isTrivialInt(int v) {
        return v >= -1 && v <= 2;
    }

    private static boolean isTrivialLong(long v) {
        return v == 0L || v == 1L;
    }

    /**
     * Build an int-pushing {@link InsnList} that evaluates to {@code value}.
     * When {@code depth > 1}, each immediate literal in the produced
     * sequence is itself recursively obfuscated &mdash; producing a
     * nested chain of {@code (depth - 1)} levels deep. Static folders
     * have to fully evaluate the entire tree before recovering the
     * original constant, raising the analysis cost geometrically.
     */
    private InsnList obfInt(int value, int depth) {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        int style = r.nextInt(4);
        int a = r.nextInt();
        InsnList il = new InsnList();
        switch (style) {
            case 0 -> {
                // value = a XOR (a XOR value)
                il.add(intLeaf(a, depth));
                il.add(intLeaf(a ^ value, depth));
                il.add(new InsnNode(Opcodes.IXOR));
            }
            case 1 -> {
                // value = (a + value) - a
                il.add(intLeaf(a + value, depth));
                il.add(intLeaf(a, depth));
                il.add(new InsnNode(Opcodes.ISUB));
            }
            case 2 -> {
                // value = a - (a - value)  (two ISUBs; doesn't algebraically
                // collapse the way ~(~value) did, so naive constant folders
                // leave both nodes in the AST).
                il.add(intLeaf(a, depth));
                il.add(intLeaf(a, depth));
                il.add(intLeaf(a - value, depth));
                il.add(new InsnNode(Opcodes.ISUB));
                il.add(new InsnNode(Opcodes.ISUB));
            }
            default -> {
                // value = a XOR b XOR ((a XOR b) XOR value); three-leg XOR
                // chain — defeats simple pairwise XOR-folding.
                int b = r.nextInt();
                il.add(intLeaf(a, depth));
                il.add(intLeaf(b, depth));
                il.add(intLeaf((a ^ b) ^ value, depth));
                il.add(new InsnNode(Opcodes.IXOR));
                il.add(new InsnNode(Opcodes.IXOR));
            }
        }
        return il;
    }

    /**
     * Return either a single-instruction push of {@code v} (depth 1, the
     * recursion base case) or another {@link #obfInt} chain at depth - 1.
     */
    private InsnList intLeaf(int v, int depth) {
        InsnList one = new InsnList();
        if (depth > 1) {
            one.add(obfInt(v, depth - 1));
        } else {
            one.add(push(v));
        }
        return one;
    }

    private InsnList obfLong(long value, int depth) {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        int style = r.nextInt(4);
        long a = r.nextLong();
        InsnList il = new InsnList();
        switch (style) {
            case 0 -> {
                il.add(longLeaf(a, depth));
                il.add(longLeaf(a ^ value, depth));
                il.add(new InsnNode(Opcodes.LXOR));
            }
            case 1 -> {
                il.add(longLeaf(a + value, depth));
                il.add(longLeaf(a, depth));
                il.add(new InsnNode(Opcodes.LSUB));
            }
            case 2 -> {
                il.add(longLeaf(a, depth));
                il.add(longLeaf(a, depth));
                il.add(longLeaf(a - value, depth));
                il.add(new InsnNode(Opcodes.LSUB));
                il.add(new InsnNode(Opcodes.LSUB));
            }
            default -> {
                long b = r.nextLong();
                il.add(longLeaf(a, depth));
                il.add(longLeaf(b, depth));
                il.add(longLeaf((a ^ b) ^ value, depth));
                il.add(new InsnNode(Opcodes.LXOR));
                il.add(new InsnNode(Opcodes.LXOR));
            }
        }
        return il;
    }

    private InsnList longLeaf(long v, int depth) {
        InsnList one = new InsnList();
        if (depth > 1) {
            one.add(obfLong(v, depth - 1));
        } else {
            one.add(new LdcInsnNode(v));
        }
        return one;
    }

    private AbstractInsnNode push(int v) {
        if (v >= -1 && v <= 5) return new InsnNode(Opcodes.ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, v);
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, v);
        return new LdcInsnNode(v);
    }
}
