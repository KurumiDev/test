package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Inserts bogus but statically opaque control-flow patterns (unreachable
 * branches, goto-spaghetti) that are correct at runtime but break structural
 * decompilation.
 */
public class FlowObfuscationTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(FlowObfuscationTransformer.class);

    @Override
    public String name() {
        return "flow-obfuscation";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        ObfuscatorConfig.FlowTechnique tech = ctx.config().flowTechnique();
        int complexity = Math.max(1, Math.min(5, ctx.config().flowComplexity()));
        int modified = 0;

        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 3) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith("$obf")) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;

                if (apply(mn, tech, complexity)) modified++;
            }
        }
        log.info("Flow-obfuscated {} methods (technique={}, complexity={})", modified, tech, complexity);
    }

    private boolean apply(MethodNode mn, ObfuscatorConfig.FlowTechnique tech, int complexity) {
        boolean any = false;
        int passes = complexity;
        for (int i = 0; i < passes; i++) {
            switch (tech) {
                case BOGUS_JUMPS -> any |= bogusJumps(mn);
                case GOTO_SPAGHETTI -> any |= gotoSpaghetti(mn);
                case EXCEPTION -> any |= exceptionWrap(mn);
                case ALL -> {
                    any |= bogusJumps(mn);
                    any |= gotoSpaghetti(mn);
                }
            }
        }
        return any;
    }

    /** Insert an opaque-true IFNE at a random safe instruction. */
    private boolean bogusJumps(MethodNode mn) {
        InsnList insns = mn.instructions;
        AbstractInsnNode target = pickInsertionPoint(mn);
        if (target == null) return false;
        LabelNode skip = new LabelNode();
        InsnList block = new InsnList();
        // (x | 1) != 0 for any x -> always true
        int x = ThreadLocalRandom.current().nextInt();
        block.add(new LdcInsnNode(x));
        block.add(new InsnNode(Opcodes.ICONST_1));
        block.add(new InsnNode(Opcodes.IOR));
        block.add(new JumpInsnNode(Opcodes.IFNE, skip));
        // Unreachable "dead" zone: ATHROW to keep verifier happy
        block.add(new InsnNode(Opcodes.ACONST_NULL));
        block.add(new InsnNode(Opcodes.ATHROW));
        block.add(skip);
        insns.insertBefore(target, block);
        return true;
    }

    /** Cut the instruction stream in two, link with GOTO back and forth. */
    private boolean gotoSpaghetti(MethodNode mn) {
        InsnList insns = mn.instructions;
        if (insns.size() < 10) return false;
        AbstractInsnNode cut = pickInsertionPoint(mn);
        if (cut == null) return false;
        LabelNode tail = new LabelNode();
        LabelNode jumpBack = new LabelNode();
        InsnList before = new InsnList();
        before.add(new JumpInsnNode(Opcodes.GOTO, tail));
        before.add(jumpBack);
        insns.insertBefore(cut, before);
        InsnList afterCut = new InsnList();
        afterCut.add(tail);
        afterCut.add(new JumpInsnNode(Opcodes.GOTO, jumpBack));
        insns.insertBefore(cut, afterCut);
        return true;
    }

    /**
     * Wrap a randomly-picked instruction in an always-false exception guard.
     * Keeps semantics while producing a try/catch block that confuses CFR.
     */
    private boolean exceptionWrap(MethodNode mn) {
        InsnList insns = mn.instructions;
        AbstractInsnNode start = pickInsertionPoint(mn);
        if (start == null) return false;
        LabelNode begin = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode after = new LabelNode();
        InsnList pre = new InsnList();
        pre.add(begin);
        insns.insertBefore(start, pre);
        InsnList post = new InsnList();
        post.add(end);
        post.add(new JumpInsnNode(Opcodes.GOTO, after));
        post.add(handler);
        post.add(new InsnNode(Opcodes.POP));
        post.add(after);
        insns.insert(start, post);
        mn.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(begin, end, handler, "java/lang/Throwable"));
        return true;
    }

    /** Pick a spot that is not inside a label chain, try block start, or init. */
    private AbstractInsnNode pickInsertionPoint(MethodNode mn) {
        AbstractInsnNode first = mn.instructions.getFirst();
        AbstractInsnNode cur = first;
        int skipped = 0;
        while (cur != null && skipped < 3) {
            cur = cur.getNext();
            skipped++;
        }
        while (cur != null) {
            int op = cur.getOpcode();
            if (op >= 0 && !isJumpOrReturn(op)) return cur;
            cur = cur.getNext();
        }
        return null;
    }

    private boolean isJumpOrReturn(int op) {
        return (op >= Opcodes.IRETURN && op <= Opcodes.RETURN)
                || op == Opcodes.ATHROW
                || op == Opcodes.GOTO
                || op == Opcodes.JSR
                || op == Opcodes.TABLESWITCH
                || op == Opcodes.LOOKUPSWITCH;
    }
}
