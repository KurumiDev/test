package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
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
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Opaque predicates backed by a class-local, runtime-seeded long[] field so
 * decompilers cannot constant-fold the condition the way they can with pure
 * literals.
 *
 * <p>Each transformed class gets:
 * <pre>
 *   private static final long[] $op = new long[4];
 *   static {
 *       $op[0] = System.nanoTime() | 1L;              // always odd
 *       $op[1] = (System.currentTimeMillis() << 1) | 3L; // always odd, != 0
 *       $op[2] = Runtime.getRuntime().availableProcessors() | 1L; // > 0
 *       $op[3] = $op[0] ^ $op[1];                     // mixed
 *   }
 * </pre>
 *
 * Predicates read {@code $op[k]} and evaluate a bit identity that is true at
 * runtime for any possible initialization value but cannot be proven by a
 * decompiler's reaching-definitions pass.
 */
public class OpaquePredicateTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(OpaquePredicateTransformer.class);

    private static final String FIELD_NAME = "$op";
    private static final String FIELD_DESC = "[J";
    private static final int SLOTS = 4;

    @Override
    public String name() {
        return "opaque-predicates";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        ObfuscatorConfig.OpaqueType type = ctx.config().opaqueType();
        int insertions = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) continue;

            boolean needSeed = false;
            for (MethodNode mn : cn.methods) {
                if (!isInjectable(mn)) continue;
                if (inject(cn, mn, type)) {
                    insertions++;
                    needSeed = true;
                }
            }
            if (needSeed) ensureSeedField(cn);
        }
        log.info("Inserted opaque predicates into {} methods", insertions);
    }

    private static boolean isInjectable(MethodNode mn) {
        if (mn.instructions == null || mn.instructions.size() < 3) return false;
        if (mn.name.startsWith("<")) return false;     // clinit / init handled separately
        if (mn.name.startsWith("$obf")) return false;
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return false;
        return true;
    }

    private boolean inject(ClassNode cn, MethodNode mn, ObfuscatorConfig.OpaqueType type) {
        AbstractInsnNode point = mn.instructions.getFirst();
        if (point == null) return false;
        LabelNode skip = new LabelNode();
        InsnList il = new InsnList();
        int strategy = choose(type);
        switch (strategy) {
            case 0 -> emitLowBitPredicate(cn, il, skip);        // $op[0] low bit == 0  ->  false
            case 1 -> emitAvailProcessorsPredicate(il, skip);   // Runtime procs > 0    ->  true
            default -> emitSelfDifferencePredicate(cn, il, skip); // $op[0] - $op[0] != 0 -> false
        }
        il.add(new InsnNode(Opcodes.ACONST_NULL));
        il.add(new InsnNode(Opcodes.ATHROW));
        il.add(skip);
        mn.instructions.insertBefore(point, il);
        return true;
    }

    // Seeded predicate: ($op[0] & 1L) == 0L  →  always false at runtime, unprovable statically.
    private static void emitLowBitPredicate(ClassNode cn, InsnList il, LabelNode skip) {
        emitLoadSlot(cn, il, 0);
        il.add(new org.objectweb.asm.tree.LdcInsnNode(1L));
        il.add(new InsnNode(Opcodes.LAND));
        il.add(new InsnNode(Opcodes.LCONST_0));
        il.add(new InsnNode(Opcodes.LCMP));
        // We want to skip on the always-true branch. "low bit == 0" is false, so IFNE skips.
        il.add(new JumpInsnNode(Opcodes.IFNE, skip));
    }

    // Runtime predicate: Runtime.availableProcessors() > 0  →  always true on any JVM.
    private static void emitAvailProcessorsPredicate(InsnList il, LabelNode skip) {
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                "()Ljava/lang/Runtime;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "availableProcessors",
                "()I", false));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPGT, skip));
    }

    // Mixed predicate: two independent reads of $op[0] cannot be folded; diff never matches a magic value.
    private static void emitSelfDifferencePredicate(ClassNode cn, InsnList il, LabelNode skip) {
        int magic = ThreadLocalRandom.current().nextInt(1, Integer.MAX_VALUE);
        emitLoadSlot(cn, il, 0);
        emitLoadSlot(cn, il, 0);
        il.add(new InsnNode(Opcodes.LSUB));
        il.add(new org.objectweb.asm.tree.LdcInsnNode((long) magic));
        il.add(new InsnNode(Opcodes.LCMP));
        il.add(new JumpInsnNode(Opcodes.IFNE, skip));
    }

    private static void emitLoadSlot(ClassNode cn, InsnList il, int slot) {
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, FIELD_NAME, FIELD_DESC));
        il.add(new IntInsnNode(Opcodes.BIPUSH, slot));
        il.add(new InsnNode(Opcodes.LALOAD));
    }

    private static void ensureSeedField(ClassNode cn) {
        boolean present = cn.fields != null && cn.fields.stream()
                .anyMatch(f -> FIELD_NAME.equals(f.name) && FIELD_DESC.equals(f.desc));
        if (!present) {
            FieldNode fn = new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL
                    | Opcodes.ACC_SYNTHETIC,
                    FIELD_NAME, FIELD_DESC, null, null);
            cn.fields.add(fn);
        }

        MethodNode clinit = null;
        for (MethodNode m : cn.methods) {
            if ("<clinit>".equals(m.name) && "()V".equals(m.desc)) {
                clinit = m;
                break;
            }
        }
        boolean created = false;
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(clinit);
            created = true;
        }
        InsnList prefix = new InsnList();
        // new long[SLOTS]
        prefix.add(new IntInsnNode(Opcodes.BIPUSH, SLOTS));
        prefix.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
        prefix.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, FIELD_NAME, FIELD_DESC));
        // slot 0 = System.nanoTime() | 1L
        seedSlot(prefix, cn, 0, SeedKind.NANO_ODD);
        // slot 1 = (System.currentTimeMillis() << 1) | 3L
        seedSlot(prefix, cn, 1, SeedKind.MILLIS_ODD);
        // slot 2 = availableProcessors() | 1
        seedSlot(prefix, cn, 2, SeedKind.PROCS_ODD);
        // slot 3 = slot[0] ^ slot[1]
        seedSlot(prefix, cn, 3, SeedKind.MIX);

        if (created) {
            clinit.instructions.insertBefore(clinit.instructions.getFirst(), prefix);
        } else {
            clinit.instructions.insert(prefix);
        }
    }

    private enum SeedKind { NANO_ODD, MILLIS_ODD, PROCS_ODD, MIX }

    private static void seedSlot(InsnList il, ClassNode cn, int slot, SeedKind kind) {
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, FIELD_NAME, FIELD_DESC));
        il.add(new IntInsnNode(Opcodes.BIPUSH, slot));
        switch (kind) {
            case NANO_ODD -> {
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime",
                        "()J", false));
                il.add(new org.objectweb.asm.tree.LdcInsnNode(1L));
                il.add(new InsnNode(Opcodes.LOR));
            }
            case MILLIS_ODD -> {
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis",
                        "()J", false));
                il.add(new InsnNode(Opcodes.ICONST_1));
                il.add(new InsnNode(Opcodes.LSHL));
                il.add(new org.objectweb.asm.tree.LdcInsnNode(3L));
                il.add(new InsnNode(Opcodes.LOR));
            }
            case PROCS_ODD -> {
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                        "()Ljava/lang/Runtime;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "availableProcessors",
                        "()I", false));
                il.add(new InsnNode(Opcodes.I2L));
                il.add(new org.objectweb.asm.tree.LdcInsnNode(1L));
                il.add(new InsnNode(Opcodes.LOR));
            }
            case MIX -> {
                // arr = $op; arr[3] = arr[0] ^ arr[1];
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, FIELD_NAME, FIELD_DESC));
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new InsnNode(Opcodes.LALOAD));
                il.add(new FieldInsnNode(Opcodes.GETSTATIC, cn.name, FIELD_NAME, FIELD_DESC));
                il.add(new InsnNode(Opcodes.ICONST_1));
                il.add(new InsnNode(Opcodes.LALOAD));
                il.add(new InsnNode(Opcodes.LXOR));
            }
        }
        il.add(new InsnNode(Opcodes.LASTORE));
    }

    private int choose(ObfuscatorConfig.OpaqueType type) {
        return switch (type) {
            case MATH -> 0;
            case RUNTIME -> 1;
            case MIXED -> ThreadLocalRandom.current().nextInt(3);
        };
    }
}
