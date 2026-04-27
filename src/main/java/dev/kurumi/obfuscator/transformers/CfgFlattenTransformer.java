package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SimpleVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Control-flow-graph flattening: rewrites each eligible method as a
 * {@code while(true) switch(state) {...}} dispatch loop. Linear order of
 * instructions in the bytecode no longer mirrors execution order, and the
 * dispatch value for the next basic block is a per-method randomized
 * integer rather than an obvious 0..N-1 sequence.
 *
 * <p>Decompilers (CFR, Fernflower, Procyon) and LLM-style reasoners have to
 * symbolically execute the switch to reconstruct the original control flow.
 * For methods with branches, this is expensive and often produces
 * labeled-loop / unreachable-block noise in the output.
 *
 * <h3>Safety</h3>
 * Flattening runs only on methods that pass every one of these checks:
 * <ul>
 *   <li>not {@code <init>} / {@code <clinit>} / synthetic decoder</li>
 *   <li>no try/catch handlers (relocating chunks across handler ranges
 *       would require rewriting every TryCatchBlockNode)</li>
 *   <li>no MONITORENTER/MONITOREXIT (moving chunks out of the monitor
 *       region is unsafe)</li>
 *   <li>ASM BasicInterpreter-derived frames show every branch target
 *       sits at a stack-empty point (so we can safely relocate the
 *       target into its own switch-case block)</li>
 *   <li>not abstract / native / too small</li>
 * </ul>
 * Any method that fails any of the above is left unchanged. That is:
 * <b>CFG flattening is strictly additive</b> &mdash; it never degrades
 * correctness, only skips unsafe candidates.
 */
public class CfgFlattenTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(CfgFlattenTransformer.class);

    private static final int MIN_INSNS = 12;   // don't bother with tiny methods
    private static final int MIN_BLOCKS = 3;   // and those with <3 basic blocks

    @Override
    public String name() {
        return "cfg-flatten";
    }

    @Override
    public boolean isEnabled(dev.kurumi.obfuscator.config.ObfuscatorConfig config) {
        return config.isTransformerEnabled("cfg-flatten");
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int flattened = 0;
        int skipped = 0;
        final String pfx = SyntheticNaming.prefix(pool);
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) continue;
            for (MethodNode mn : cn.methods) {
                if (!eligible(mn, pfx)) { continue; }
                try {
                    if (flatten(cn, mn)) {
                        flattened++;
                    } else {
                        skipped++;
                    }
                } catch (Throwable t) {
                    // Paranoid fallback: flatten() never mutates
                    // mn.instructions until its very last step, so a
                    // mid-flight exception here leaves the method
                    // untouched and we just record the skip.
                    skipped++;
                    log.debug("cfg-flatten: bailed on {}.{}: {}", cn.name, mn.name, t.toString());
                }
            }
        }
        log.info("CFG-flattened {} methods (skipped {})", flattened, skipped);
    }

    private static boolean eligible(MethodNode mn, String pfx) {
        if (mn.name.startsWith("<")) return false;
        if (mn.name.startsWith(pfx)) return false;
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return false;
        if (mn.instructions == null || mn.instructions.size() < MIN_INSNS) return false;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return false;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int op = insn.getOpcode();
            if (op == Opcodes.MONITORENTER || op == Opcodes.MONITOREXIT) return false;
            if (op == Opcodes.JSR || op == Opcodes.RET) return false;
        }
        return true;
    }

    /**
     * Actually rewrites {@code mn.instructions}. Returns {@code true} on
     * successful flattening, {@code false} if we decided mid-flight to
     * bail (leaves the method unchanged).
     */
    private boolean flatten(ClassNode cn, MethodNode mn) throws AnalyzerException {
        // --- 1. Compute frames so we know which instructions are
        //        stack-empty. Any jump target that is NOT stack-empty
        //        cannot safely be moved into its own switch case.
        //        Earlier passes may have inflated the actual stack use
        //        without updating mn.maxStack (the final ClassWriter
        //        recomputes it via COMPUTE_MAXS). Temporarily set a
        //        generous bound so the Analyzer doesn't abort.
        int savedMaxStack = mn.maxStack;
        mn.maxStack = Math.max(mn.maxStack, 256);
        Analyzer<BasicValue> analyzer = new Analyzer<>(new BasicInterpreter());
        Frame<BasicValue>[] frames;
        try {
            frames = analyzer.analyze(cn.name, mn);
        } finally {
            mn.maxStack = savedMaxStack;
        }

        InsnList insns = mn.instructions;

        // Collect jump targets used anywhere in the method.
        Set<LabelNode> jumpTargets = new HashSet<>();
        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode jin) {
                jumpTargets.add(jin.label);
            } else if (insn instanceof TableSwitchInsnNode ts) {
                if (ts.dflt != null) jumpTargets.add(ts.dflt);
                if (ts.labels != null) jumpTargets.addAll(ts.labels);
            } else if (insn instanceof LookupSwitchInsnNode ls) {
                if (ls.dflt != null) jumpTargets.add(ls.dflt);
                if (ls.labels != null) jumpTargets.addAll(ls.labels);
            }
        }

        // Map label -> its instruction index.
        // If any jump target is at a non-stack-empty frame, bail.
        Map<LabelNode, Integer> labelToIdx = new HashMap<>();
        for (int i = 0; i < insns.size(); i++) {
            AbstractInsnNode a = insns.get(i);
            if (a instanceof LabelNode ln) labelToIdx.put(ln, i);
        }
        for (LabelNode t : jumpTargets) {
            Integer idx = labelToIdx.get(t);
            if (idx == null) { log.debug("bail {}.{}: jump target label missing", cn.name, mn.name); return false; }
            // Frames are attached to "real" instructions. Labels themselves
            // don't carry a frame, so inspect the next real instruction.
            int probe = idx;
            while (probe < insns.size() - 1 && frames[probe] == null) probe++;
            Frame<BasicValue> f = frames[probe];
            if (f == null) continue; // unreachable
            if (f.getStackSize() != 0) {
                log.debug("bail {}.{}: jump target at stack-size {}", cn.name, mn.name, f.getStackSize());
                return false;
            }
        }

        // --- 2. Split the instruction list into basic blocks whose
        //        starts are either (a) the first real instruction, or
        //        (b) any stack-empty jump target.
        List<Block> blocks = new ArrayList<>();
        Block current = new Block();
        current.startLabel = null;
        current.startIndex = 0;
        for (int i = 0; i < insns.size(); i++) {
            AbstractInsnNode a = insns.get(i);
            if (a instanceof LabelNode ln && jumpTargets.contains(ln)) {
                if (i == 0) {
                    current.startLabel = ln;
                    continue;
                }
                current.endIndexExclusive = i;
                blocks.add(current);
                current = new Block();
                current.startLabel = ln;
                current.startIndex = i;
            }
        }
        current.endIndexExclusive = insns.size();
        blocks.add(current);

        if (blocks.size() < MIN_BLOCKS) return false;

        // --- 3. Give each block a random state id and a fresh LabelNode.
        long seed = stableSeed(cn.name + "." + mn.name + mn.desc);
        Random rng = new Random(seed);
        Set<Integer> usedIds = new HashSet<>();
        int[] stateId = new int[blocks.size()];
        LabelNode[] blockLabel = new LabelNode[blocks.size()];
        for (int i = 0; i < blocks.size(); i++) {
            int id;
            do {
                id = rng.nextInt(0x3FFFFFFF);
            } while (!usedIds.add(id));
            stateId[i] = id;
            blockLabel[i] = new LabelNode();
        }
        // Per-method dispatch key. Stored values are XORed with this key
        // and the LOOKUPSWITCH keys are also pre-XORed at compile time, so
        // the dispatch table looks like noise unless you reconstruct the
        // key. The key itself is computed at method entry from a literal
        // {@code k} and the runtime class identity hash {@code h}, where
        // we emit the literal as {@code k = expectedKey ^ h}. At runtime
        // {@code k ^ h == expectedKey}; at static-analysis time the
        // LOOKUPSWITCH keys are not constants relative to the visible
        // {@code stateId[]} sequence.
        //
        // This is the same runtime class-identity binding trick used by
        // BlobStringTransformer and EncryptedClassVaultTransformer for
        // their decoder seeds: {@code MethodHandles.lookup().lookupClass()
        // .getName().hashCode()}.
        int expectedKey = rng.nextInt() | 1;
        int classNameHash = cn.name.replace('/', '.').hashCode();
        int literalKey = expectedKey ^ classNameHash;
        // Remember original start labels so intra-method jumps can be
        // retargeted to the block's new label. We also build a label
        // clone map for AbstractInsnNode.clone() so jumps in cloned
        // instructions still resolve sensibly (cloned jumps pointing
        // at a known block start land on blockLabel[i]; unknown labels
        // map to themselves, which should never happen because we
        // validated all jump targets above).
        Map<LabelNode, Integer> startLabelToBlock = new HashMap<>();
        Map<LabelNode, LabelNode> labelCloneMap = new HashMap<>();
        for (int i = 0; i < blocks.size(); i++) {
            if (blocks.get(i).startLabel != null) {
                startLabelToBlock.put(blocks.get(i).startLabel, i);
                labelCloneMap.put(blocks.get(i).startLabel, blockLabel[i]);
            }
        }

        // State variable slot: first unused local after method args.
        // Plus a key slot one past it for the runtime-derived dispatch key.
        int stateVar = Math.max(mn.maxLocals, computeInitialLocals(mn));
        int keyVar = stateVar + 1;
        int newMaxLocals = keyVar + 1;

        // --- 4. Build the flat body.
        LabelNode loopStart = new LabelNode();
        LabelNode defaultLabel = new LabelNode();

        InsnList out = new InsnList();
        // Entry preamble: compute keyVar = literalKey ^ classNameHash via
        //   MethodHandles.lookup().lookupClass().getName().hashCode().
        // At runtime keyVar == expectedKey. At static-analysis time, the
        // value of keyVar is opaque without symbolic execution of
        // MethodHandles.
        out.add(new LdcInsnNode(Integer.valueOf(literalKey)));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/invoke/MethodHandles", "lookup",
                "()Ljava/lang/invoke/MethodHandles$Lookup;", false));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", "lookupClass",
                "()Ljava/lang/Class;", false));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Class", "getName", "()Ljava/lang/String;", false));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/String", "hashCode", "()I", false));
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, keyVar));

        // entry: state = stateId[0] ^ expectedKey  (encoded form already)
        pushInt(out, stateId[0] ^ expectedKey);
        out.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
        out.add(loopStart);
        out.add(new VarInsnNode(Opcodes.ILOAD, stateVar));
        // Build LOOKUPSWITCH entries with each key XOR-encoded.
        // The JVM requires keys be sorted; we sort the encoded values.
        int[] keys = new int[stateId.length];
        for (int i = 0; i < keys.length; i++) keys[i] = stateId[i] ^ expectedKey;
        Integer[] order = new Integer[keys.length];
        for (int i = 0; i < keys.length; i++) order[i] = i;
        java.util.Arrays.sort(order, (a, b) -> Integer.compare(keys[a], keys[b]));
        int[] sortedKeys = new int[keys.length];
        LabelNode[] sortedLabels = new LabelNode[keys.length];
        for (int i = 0; i < keys.length; i++) {
            sortedKeys[i] = keys[order[i]];
            sortedLabels[i] = blockLabel[order[i]];
        }
        out.add(new LookupSwitchInsnNode(defaultLabel, sortedKeys, sortedLabels));

        // Emit each block.
        for (int bi = 0; bi < blocks.size(); bi++) {
            Block b = blocks.get(bi);
            out.add(blockLabel[bi]);

            // Copy original instructions, rewriting jumps so that jumps
            // to any known block start become "set state, goto loopStart".
            // A conditional jump gets an intermediate label just after the
            // conditional that encodes the "taken" state transition.
            List<AbstractInsnNode> body = new ArrayList<>();
            for (int idx = b.startIndex; idx < b.endIndexExclusive; idx++) {
                body.add(insns.get(idx));
            }
            boolean endsWithTerminator = false;
            for (int k = 0; k < body.size(); k++) {
                AbstractInsnNode a = body.get(k);
                // Drop all LabelNodes: the only semantically significant
                // ones were jump targets, and we verified every jump
                // target is at a block start (handled via blockLabel[]).
                if (a instanceof LabelNode) continue;
                if (a instanceof FrameNode) continue;
                if (a instanceof JumpInsnNode jin) {
                    Integer targetBlock = startLabelToBlock.get(jin.label);
                    if (targetBlock == null) {
                        // A jump to a label that isn't a block boundary
                        // (shouldn't happen because we validated above).
                        // Refuse the whole method to stay safe.
                        return false;
                    }
                    if (jin.getOpcode() == Opcodes.GOTO) {
                        emitTransition(out, stateId[targetBlock], stateVar, keyVar, loopStart);
                        endsWithTerminator = true;
                    } else {
                        LabelNode trampoline = new LabelNode();
                        LabelNode after = new LabelNode();
                        out.add(new JumpInsnNode(jin.getOpcode(), trampoline));
                        out.add(new JumpInsnNode(Opcodes.GOTO, after));
                        out.add(trampoline);
                        emitTransition(out, stateId[targetBlock], stateVar, keyVar, loopStart);
                        out.add(after);
                    }
                } else if (a instanceof TableSwitchInsnNode || a instanceof LookupSwitchInsnNode) {
                    // Rewriting indexed switches as per-branch state
                    // transitions needs a label-clone map; not worth it
                    // for the rare methods that contain one. Refuse.
                    return false;
                } else if (isReturn(a) || a.getOpcode() == Opcodes.ATHROW) {
                    out.add(a.clone(labelCloneMap));
                    endsWithTerminator = true;
                } else if (a instanceof LineNumberNode) {
                    continue;
                } else {
                    out.add(a.clone(labelCloneMap));
                }
            }
            // Fall-through to next block -> set its state and goto loopStart.
            if (!endsWithTerminator) {
                int next = bi + 1;
                if (next < blocks.size()) {
                    emitTransition(out, stateId[next], stateVar, keyVar, loopStart);
                } else {
                    // Fall off the end — shouldn't happen in valid bytecode,
                    // but if it does, throw to keep the verifier happy.
                    out.add(new InsnNode(Opcodes.ACONST_NULL));
                    out.add(new InsnNode(Opcodes.ATHROW));
                }
            }
        }

        // Default switch branch: throw. Reached only if the state var
        // is corrupted at runtime, which in practice never happens.
        out.add(defaultLabel);
        out.add(new InsnNode(Opcodes.ACONST_NULL));
        out.add(new InsnNode(Opcodes.ATHROW));

        // --- 5. Swap the instruction list in, then verify the result.
        //        If the mutated method fails verification (most commonly
        //        because a local variable live across a jump boundary was
        //        set up by fall-through in the original code but the
        //        dispatcher loses that init edge), revert to the original
        //        so the method stays correct even if unflattened.
        InsnList savedInsns = mn.instructions;
        List<LocalVariableNode> savedLVs = mn.localVariables;
        int savedOuterMaxStack = mn.maxStack;
        int savedMaxLocals = mn.maxLocals;

        mn.instructions = out;
        mn.maxLocals = newMaxLocals;
        mn.localVariables = null;          // existing ranges are now invalid
        // Preamble pushes int + Class object + ... up to depth 2; transitions
        // push int + int and IXOR. Keep slack for safety.
        mn.maxStack = Math.max(mn.maxStack, 4);

        if (!verifyAfterFlatten(cn, mn)) {
            log.debug("cfg-flatten: verify failed on {}.{}, reverting", cn.name, mn.name);
            mn.instructions = savedInsns;
            mn.localVariables = savedLVs;
            mn.maxStack = savedOuterMaxStack;
            mn.maxLocals = savedMaxLocals;
            return false;
        }
        return true;
    }

    /**
     * Runs a SimpleVerifier on the mutated method and returns true iff
     * no frame-level type mismatch is detected. SimpleVerifier's type
     * lattice is much stricter than BasicInterpreter's, so any
     * "Expected X, but found top" error that would surface in the
     * final JVM verifier is caught here.
     */
    private static boolean verifyAfterFlatten(ClassNode cn, MethodNode mn) {
        SimpleVerifier sv = new SimpleVerifier(
                Type.getObjectType(cn.name),
                cn.superName == null ? null : Type.getObjectType(cn.superName),
                null,
                (cn.access & Opcodes.ACC_INTERFACE) != 0);
        // Use the CONTEXT class loader to resolve types referenced by the
        // method. SimpleVerifier resolves them via Class.forName — missing
        // classes raise TypeNotPresentException which we treat as a verify
        // failure and revert. That is the safe choice for obfuscated
        // plugins that import runtime-provided APIs (e.g. Bukkit). The
        // cost is a handful of skipped methods; the benefit is never
        // emitting bytecode that the actual JVM will reject.
        sv.setClassLoader(Thread.currentThread().getContextClassLoader());
        Analyzer<BasicValue> analyzer = new Analyzer<>(sv);
        int savedMaxStack = mn.maxStack;
        mn.maxStack = Math.max(mn.maxStack, 256);
        try {
            analyzer.analyze(cn.name, mn);
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            mn.maxStack = savedMaxStack;
        }
    }

    /**
     * Emits {@code stateVar = stateId[next] ^ keyVar; goto loopStart}.
     * The XOR with the runtime-derived {@code keyVar} keeps the encoded
     * state value in {@code stateVar} in lock-step with the LOOKUPSWITCH
     * keys (which are also encoded as {@code stateId ^ expectedKey}).
     */
    private static void emitTransition(InsnList out, int rawStateId, int stateVar,
                                       int keyVar, LabelNode loopStart) {
        pushInt(out, rawStateId);
        out.add(new VarInsnNode(Opcodes.ILOAD, keyVar));
        out.add(new InsnNode(Opcodes.IXOR));
        out.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
        out.add(new JumpInsnNode(Opcodes.GOTO, loopStart));
    }

    /** Integer push helper that picks the most compact encoding. */
    private static void pushInt(InsnList out, int v) {
        if (v >= -1 && v <= 5) {
            out.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            out.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            out.add(new IntInsnNode(Opcodes.SIPUSH, v));
        } else {
            out.add(new LdcInsnNode(Integer.valueOf(v)));
        }
    }

    private static boolean isReturn(AbstractInsnNode a) {
        int op = a.getOpcode();
        return op == Opcodes.RETURN || op == Opcodes.IRETURN || op == Opcodes.LRETURN
                || op == Opcodes.FRETURN || op == Opcodes.DRETURN || op == Opcodes.ARETURN;
    }

    private static int computeInitialLocals(MethodNode mn) {
        int slots = 0;
        if ((mn.access & Opcodes.ACC_STATIC) == 0) slots++;
        for (Type t : Type.getArgumentTypes(mn.desc)) slots += t.getSize();
        return slots;
    }

    private static long stableSeed(String s) {
        long h = 1125899906842597L;
        for (int i = 0; i < s.length(); i++) {
            h = 31 * h + s.charAt(i);
        }
        return h;
    }

    private static final class Block {
        LabelNode startLabel;
        int startIndex;
        int endIndexExclusive;
    }
}
