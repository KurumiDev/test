package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Replaces numeric constants with arithmetic / bitwise equivalents. By default
 * only touches "magic numbers" (abs value &gt; 10) so loop counters stay readable
 * at no cost.
 *
 * <h2>Defeating constant folding</h2>
 *
 * <p>The recursive XOR / SUB chains produced by {@link #obfInt(int, int)}
 * are syntactically obscure but algebraically pure: they reduce, by
 * pure constant folding, to the original literal. Any decompiler with a
 * mid-end pass &mdash; CFR, Fernflower, Procyon, IntelliJ's bytecode
 * viewer &mdash; happily prints the original integer right back.
 *
 * <p>To break this, when {@link ObfuscatorConfig#numberRuntimeKeyed()}
 * is on (the default in v2.1.3+), every class that has at least one
 * obfuscated int constant gets a per-class synthetic static field
 * <code>$&lt;prefix&gt;numKey_&lt;hash&gt;</code> initialised in
 * {@code <clinit>} from <strong>runtime</strong> state &mdash;
 * specifically <code>"&lt;own-class-name&gt;".hashCode() ^ buildSalt</code>.
 * Each obfuscated literal is then masked at build time with the
 * obfuscator's expected runtime-key value, and the bytecode emits a
 * {@code GETSTATIC numKey; IXOR;} as the final reduction step. At
 * runtime, the masked value XOR'd with the field's actual value
 * recovers the original literal. At compile / decompile time, the
 * decompiler sees an {@code IXOR} against an opaque field whose value
 * is computed by {@code String.hashCode()} on a runtime string &mdash;
 * a method call decompilers preserve verbatim. So the constant cannot
 * be folded statically.
 *
 * <p>The runtime key derivation uses {@link String#hashCode()} on the
 * post-rename class name, which is deterministic across JVMs (the JLS
 * specifies the algorithm) but is preserved as a method invocation by
 * every major decompiler. Pre-computing the answer would require the
 * decompiler to evaluate Java method calls during analysis, which it
 * does not do.
 *
 * <p>The runtime key is initialised lazily by the JVM exactly once
 * during the class's first use, so the per-literal cost is one
 * {@code GETSTATIC} + one {@code IXOR}. No allocation, no synchronisation.
 */
public class NumberObfuscationTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(NumberObfuscationTransformer.class);

    /** Field-name infix that identifies our runtime-keyed XOR slot. */
    private static final String NUM_KEY_INFIX = "numKey_";

    @Override
    public String name() {
        return "number-obfuscation";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        boolean onlyMagic = ctx.config().numberOnlyMagic();
        boolean runtimeKeyed = ctx.config().numberRuntimeKeyed();
        int depth = ctx.config().numberDepth();
        int replaced = 0;
        int classesWithKey = 0;
        // Per-JAR synthetic prefix: skip our own emitted synthetics so we
        // don't, e.g., obfuscate the magic constants baked into the
        // string-decoder LCG step. Earlier versions hard-coded "$obf"
        // here; that left a single literal in the codebase pointing at
        // the obfuscator's own synthetic naming convention.
        final String pfx = SyntheticNaming.prefix(pool);
        // Per-build salt that goes into every per-class runtime-key
        // derivation. Chosen once per pipeline run so two builds of the
        // same input yield different obfuscated bytecode.
        final int buildSalt = ThreadLocalRandom.current().nextInt() | 1;
        for (ClassNode cn : pool.allClassNodes()) {
            if (cn.methods == null) continue;
            // Decide up-front whether this class is eligible for a
            // runtime-key field. Interfaces / modules / annotations have
            // no <clinit> body to hook into in a way that survives
            // verifier checks reliably, so skip them.
            boolean canHaveKey = runtimeKeyed
                    && (cn.access & Opcodes.ACC_INTERFACE) == 0
                    && (cn.access & Opcodes.ACC_MODULE) == 0
                    && (cn.access & Opcodes.ACC_ANNOTATION) == 0;

            String numKeyField = null;
            int runtimeKeyExpected = 0;
            boolean classNeedsKey = false;

            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith(pfx)) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    Integer iv = intConstant(insn);
                    if (iv != null) {
                        if (onlyMagic && isTrivialInt(iv)) continue;
                        if (canHaveKey && numKeyField == null) {
                            // Lazily pick a field name and compute the
                            // expected runtime-key the first time we
                            // need to obfuscate any int in this class.
                            numKeyField = pickNumKeyName(pfx, cn.name, buildSalt);
                            runtimeKeyExpected = expectedRuntimeKey(cn.name, buildSalt);
                            classNeedsKey = true;
                        }
                        InsnList rep = obfInt(iv, depth, numKeyField, cn.name, runtimeKeyExpected);
                        mn.instructions.insert(insn, rep);
                        mn.instructions.remove(insn);
                        replaced++;
                        continue;
                    }
                    Long lv = longConstant(insn);
                    if (lv != null) {
                        if (onlyMagic && isTrivialLong(lv)) continue;
                        // Long literals stay non-runtime-keyed for now;
                        // a separate $numKeyL slot would double the
                        // <clinit> pollution and the pure-arithmetic
                        // chain is already expensive to fold for a
                        // 64-bit literal. Revisit if profiling shows
                        // CFR collapsing them.
                        InsnList rep = obfLong(lv, depth);
                        mn.instructions.insert(insn, rep);
                        mn.instructions.remove(insn);
                        replaced++;
                    }
                }
            }

            if (classNeedsKey) {
                installRuntimeKeyField(cn, numKeyField, buildSalt);
                classesWithKey++;
            }
        }
        log.info("Obfuscated {} numeric constants (depth={}, runtime-keyed-classes={})",
                replaced, depth, classesWithKey);
    }

    /**
     * Adds the synthetic int field, then prepends an initialisation
     * sequence to the class's {@code <clinit>} (creating one if
     * absent) that computes
     * {@code $numKey = "<class-name>".hashCode() ^ buildSalt}.
     */
    private static void installRuntimeKeyField(ClassNode cn, String fieldName, int buildSalt) {
        if (cn.fields == null) cn.fields = new ArrayList<>();
        // De-dup if a previous pass / re-run already added it.
        for (FieldNode fn : cn.fields) {
            if (fn.name.equals(fieldName)) return;
        }
        cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                fieldName, "I", null, null));

        MethodNode clinit = findOrCreateClinit(cn);
        // Build:
        //   LDC "<dotted-class-name>"
        //   INVOKEVIRTUAL String.hashCode ()I
        //   LDC <buildSalt>
        //   IXOR
        //   PUTSTATIC <cn>.<fieldName> : I
        InsnList init = new InsnList();
        init.add(new LdcInsnNode(cn.name.replace('/', '.')));
        init.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/String", "hashCode", "()I", false));
        init.add(new LdcInsnNode(buildSalt));
        init.add(new InsnNode(Opcodes.IXOR));
        init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, fieldName, "I"));

        clinit.instructions.insert(init);
    }

    private static MethodNode findOrCreateClinit(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            if (mn.name.equals("<clinit>") && mn.desc.equals("()V")) {
                return mn;
            }
        }
        MethodNode mn = new MethodNode(
                Opcodes.ACC_STATIC,
                "<clinit>", "()V", null, null);
        mn.instructions.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
        return mn;
    }

    private static String pickNumKeyName(String prefix, String internalName, int buildSalt) {
        int h = (internalName.hashCode() * 0x9E3779B1) ^ buildSalt;
        return prefix + NUM_KEY_INFIX + Integer.toHexString(h & 0x7FFFFFFF);
    }

    /**
     * The integer the obfuscator expects {@code <clinit>} to write
     * into the runtime-key field. Must match the bytecode emitted by
     * {@link #installRuntimeKeyField} exactly.
     */
    private static int expectedRuntimeKey(String internalName, int buildSalt) {
        return internalName.replace('/', '.').hashCode() ^ buildSalt;
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
     *
     * <p>If {@code numKeyField} is non-null, we mask the target value
     * with the obfuscator's expected runtime-key, generate the
     * arithmetic chain for the masked value, and append a
     * {@code GETSTATIC; IXOR;} so the runtime XOR with the per-class
     * field recovers the original. The decompiler cannot fold this
     * because the field's value is initialised by a {@code String.hashCode()}
     * call that decompilers preserve verbatim.
     */
    private InsnList obfInt(int value, int depth, String numKeyField,
                            String ownerInternal, int runtimeKeyExpected) {
        if (numKeyField != null) {
            int masked = value ^ runtimeKeyExpected;
            InsnList il = obfIntChain(masked, depth);
            il.add(new FieldInsnNode(Opcodes.GETSTATIC, ownerInternal, numKeyField, "I"));
            il.add(new InsnNode(Opcodes.IXOR));
            return il;
        }
        return obfIntChain(value, depth);
    }

    /** Pure-arithmetic obfuscation chain whose decompiled form folds back to {@code value}. */
    private InsnList obfIntChain(int value, int depth) {
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
                // value = a - ((a + c) - (c + value))
                //       = a - (a - value) = value
                // Two ISUBs, three obscured leaves (none of them is `value`
                // itself), so the constant is hidden even at depth=1 and
                // doesn't algebraically collapse for naive constant folders.
                int c = r.nextInt();
                il.add(intLeaf(a, depth));
                il.add(intLeaf(a + c, depth));
                il.add(intLeaf(c + value, depth));
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
     * recursion base case) or another {@link #obfIntChain} chain at depth - 1.
     *
     * <p>Leaves are never themselves runtime-keyed: the masking only
     * happens once, at the outermost layer of {@link #obfInt}. Doing
     * it at every leaf would push the field-load through {@code depth}
     * levels of arithmetic and break the algebraic folding the chain
     * relies on.
     */
    private InsnList intLeaf(int v, int depth) {
        InsnList one = new InsnList();
        if (depth > 1) {
            one.add(obfIntChain(v, depth - 1));
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
                // value = a - ((a + c) - (c + value)); see int variant.
                long c = r.nextLong();
                il.add(longLeaf(a, depth));
                il.add(longLeaf(a + c, depth));
                il.add(longLeaf(c + value, depth));
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
