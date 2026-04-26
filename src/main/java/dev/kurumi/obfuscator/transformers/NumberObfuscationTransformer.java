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
        int replaced = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith("$obf")) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    Integer iv = intConstant(insn);
                    if (iv != null) {
                        if (onlyMagic && isTrivialInt(iv)) continue;
                        InsnList rep = obfInt(iv);
                        mn.instructions.insert(insn, rep);
                        mn.instructions.remove(insn);
                        replaced++;
                        continue;
                    }
                    Long lv = longConstant(insn);
                    if (lv != null) {
                        if (onlyMagic && isTrivialLong(lv)) continue;
                        InsnList rep = obfLong(lv);
                        mn.instructions.insert(insn, rep);
                        mn.instructions.remove(insn);
                        replaced++;
                    }
                }
            }
        }
        log.info("Obfuscated {} numeric constants", replaced);
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

    private InsnList obfInt(int value) {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        int style = r.nextInt(4);
        int a = r.nextInt();
        InsnList il = new InsnList();
        switch (style) {
            case 0 -> {
                // value = a XOR (a XOR value)
                il.add(push(a));
                il.add(push(a ^ value));
                il.add(new InsnNode(Opcodes.IXOR));
            }
            case 1 -> {
                // value = (a + value) - a
                il.add(push(a + value));
                il.add(push(a));
                il.add(new InsnNode(Opcodes.ISUB));
            }
            case 2 -> {
                // value = a - (a - value)  (two ISUBs; doesn't algebraically
                // collapse the way ~(~value) did, so naive constant folders
                // leave both nodes in the AST).
                il.add(push(a));
                il.add(push(a));
                il.add(push(a - value));
                il.add(new InsnNode(Opcodes.ISUB));
                il.add(new InsnNode(Opcodes.ISUB));
            }
            default -> {
                // value = a XOR b XOR ((a XOR b) XOR value); three-leg XOR
                // chain — defeats simple pairwise XOR-folding.
                int b = r.nextInt();
                il.add(push(a));
                il.add(push(b));
                il.add(push((a ^ b) ^ value));
                il.add(new InsnNode(Opcodes.IXOR));
                il.add(new InsnNode(Opcodes.IXOR));
            }
        }
        return il;
    }

    private InsnList obfLong(long value) {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        int style = r.nextInt(4);
        long a = r.nextLong();
        InsnList il = new InsnList();
        switch (style) {
            case 0 -> {
                // value = a XOR (a XOR value)
                il.add(new LdcInsnNode(a));
                il.add(new LdcInsnNode(a ^ value));
                il.add(new InsnNode(Opcodes.LXOR));
            }
            case 1 -> {
                // value = (a + value) - a
                il.add(new LdcInsnNode(a + value));
                il.add(new LdcInsnNode(a));
                il.add(new InsnNode(Opcodes.LSUB));
            }
            case 2 -> {
                // value = a - (a - value)
                il.add(new LdcInsnNode(a));
                il.add(new LdcInsnNode(a));
                il.add(new LdcInsnNode(a - value));
                il.add(new InsnNode(Opcodes.LSUB));
                il.add(new InsnNode(Opcodes.LSUB));
            }
            default -> {
                // value = a XOR b XOR ((a XOR b) XOR value); three-leg XOR chain
                long b = r.nextLong();
                il.add(new LdcInsnNode(a));
                il.add(new LdcInsnNode(b));
                il.add(new LdcInsnNode((a ^ b) ^ value));
                il.add(new InsnNode(Opcodes.LXOR));
                il.add(new InsnNode(Opcodes.LXOR));
            }
        }
        return il;
    }

    private AbstractInsnNode push(int v) {
        if (v >= -1 && v <= 5) return new InsnNode(Opcodes.ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, v);
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, v);
        return new LdcInsnNode(v);
    }
}
