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
import org.objectweb.asm.tree.MethodInsnNode;
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
        final String pfx = SyntheticNaming.prefix(pool);

        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 3) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith(pfx)) continue;
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
                    any |= exceptionWrap(mn);
                }
            }
        }
        return any;
    }

    /**
     * Insert an opaque-true IFNE at a random safe instruction.
     *
     * <p>The predicate uses {@code (System.nanoTime() | 1L) != 0L}. nanoTime
     * is opaque to every static analyzer (its return value is unknowable
     * without executing the method); {@code | 1L} guarantees the result is
     * non-zero at runtime. A previous version of this routine emitted
     * {@code (LDC | 1) != 0}, which is a closed-form constant any partial
     * evaluator (CFR's deadcode pass, Vineflower's algebraic simplifier)
     * collapses to {@code true} and prunes the {@code ATHROW} branch
     * outright. nanoTime() blocks that pruning: the analyzer cannot know
     * the value is non-zero at compile time, so it has to keep the branch.
     */
    private boolean bogusJumps(MethodNode mn) {
        InsnList insns = mn.instructions;
        AbstractInsnNode target = pickInsertionPoint(mn);
        if (target == null) return false;
        LabelNode skip = new LabelNode();
        InsnList block = new InsnList();
        // (System.nanoTime() | 1L) != 0L  --  always true at runtime, opaque to static analysis.
        block.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime",
                "()J", false));
        block.add(new LdcInsnNode(1L));
        block.add(new InsnNode(Opcodes.LOR));
        block.add(new InsnNode(Opcodes.LCONST_0));
        block.add(new InsnNode(Opcodes.LCMP));
        block.add(new JumpInsnNode(Opcodes.IFNE, skip));
        // Unreachable "dead" zone: ATHROW to keep verifier happy
        block.add(new InsnNode(Opcodes.ACONST_NULL));
        block.add(new InsnNode(Opcodes.ATHROW));
        block.add(skip);
        insns.insertBefore(target, block);
        return true;
    }

    /**
     * Rotate the instruction stream around a midpoint. Original flow A; B
     * (with B reachable via fall-through) becomes:
     *
     * <pre>
     *   GOTO first_half       // forces decompilers to abandon linear reading
     *   second_label:
     *     B
     *   first_half:
     *     A
     *     GOTO second_label
     * </pre>
     *
     * <p>Semantically identical: control still flows A → B. But the physical
     * order in the bytecode is B, A — CFR and Fernflower's structured
     * recognizers get confused and emit labeled loops or unreachable-block
     * warnings.
     *
     * <p>Skipped if the method contains try/catch blocks (moving chunks across
     * handler ranges would require rewriting every TryCatchBlockNode's begin/end).
     */
    private boolean gotoSpaghetti(MethodNode mn) {
        InsnList insns = mn.instructions;
        if (insns.size() < 10) return false;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return false;

        // Pick a cut point: a label node, not too close to either end.
        LabelNode cutLabel = pickSplitLabel(mn);
        if (cutLabel == null) return false;

        AbstractInsnNode first = insns.getFirst();
        AbstractInsnNode last = insns.getLast();
        if (first == null || last == null) return false;

        LabelNode firstHalfLbl = new LabelNode();

        // Detach chunk A = [first .. node-before-cutLabel] into a new list.
        InsnList chunkA = new InsnList();
        AbstractInsnNode cursor = first;
        while (cursor != null && cursor != cutLabel) {
            AbstractInsnNode next = cursor.getNext();
            insns.remove(cursor);
            chunkA.add(cursor);
            cursor = next;
        }
        // Sanity: if chunk A is empty or cutLabel not found, bail.
        if (cursor != cutLabel || chunkA.size() == 0) {
            // Restore if we corrupted anything (shouldn't happen — just rebuild)
            insns.insert(chunkA);
            return false;
        }

        // Prepend "GOTO firstHalfLbl" at the (new) head of insns (before cutLabel).
        InsnList newHead = new InsnList();
        newHead.add(new JumpInsnNode(Opcodes.GOTO, firstHalfLbl));
        insns.insert(newHead);

        // Append firstHalfLbl, chunkA, GOTO cutLabel at the very end.
        InsnList tail = new InsnList();
        tail.add(firstHalfLbl);
        tail.add(chunkA);
        tail.add(new JumpInsnNode(Opcodes.GOTO, cutLabel));
        insns.add(tail);
        return true;
    }

    private LabelNode pickSplitLabel(MethodNode mn) {
        InsnList insns = mn.instructions;
        java.util.List<LabelNode> candidates = new java.util.ArrayList<>();
        int idx = 0;
        int size = insns.size();
        for (AbstractInsnNode node : insns.toArray()) {
            idx++;
            // Keep a middle band; avoid first 3 and last 3 insns.
            if (idx <= 3 || idx >= size - 2) continue;
            if (node instanceof LabelNode lbl) candidates.add(lbl);
        }
        if (candidates.isEmpty()) return null;
        return candidates.get(ThreadLocalRandom.current().nextInt(candidates.size()));
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

        // The handler rethrows unconditionally. That keeps the handler's
        // terminating stack state from propagating into `after:` — only the
        // normal GOTO path (stack === stack at `end`) reaches `after:`, so the
        // verifier never sees the "incompatible stack heights" conflict that
        // happens when a POP'd handler falls through into an arbitrary
        // mid-expression point.
        InsnList post = new InsnList();
        post.add(end);
        post.add(new JumpInsnNode(Opcodes.GOTO, after));
        post.add(handler);
        post.add(new InsnNode(Opcodes.ATHROW));
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
