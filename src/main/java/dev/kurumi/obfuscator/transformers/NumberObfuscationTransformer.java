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
                    Integer value = intConstant(insn);
                    if (value == null) continue;
                    if (onlyMagic && Math.abs(value) < 10) continue;
                    InsnList rep = obfInt(value);
                    if (rep == null) continue;
                    mn.instructions.insert(insn, rep);
                    mn.instructions.remove(insn);
                    replaced++;
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

    private InsnList obfInt(int value) {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        int style = r.nextInt(3);
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
            default -> {
                // value = ~(~value)
                il.add(push(~value));
                il.add(new InsnNode(Opcodes.ICONST_M1));
                il.add(new InsnNode(Opcodes.IXOR));
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
