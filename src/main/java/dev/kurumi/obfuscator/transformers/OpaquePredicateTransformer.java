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
 * Injects predicates whose value is trivially constant at runtime but not
 * (easily) statically decidable, forcing decompilers to emit dead-branch spam.
 */
public class OpaquePredicateTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(OpaquePredicateTransformer.class);

    @Override
    public String name() {
        return "opaque-predicates";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        ObfuscatorConfig.OpaqueType type = ctx.config().opaqueType();
        int insertions = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 3) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith("$obf")) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;

                if (inject(mn, type)) insertions++;
            }
        }
        log.info("Inserted opaque predicates into {} methods", insertions);
    }

    private boolean inject(MethodNode mn, ObfuscatorConfig.OpaqueType type) {
        AbstractInsnNode point = mn.instructions.getFirst();
        if (point == null) return false;
        LabelNode skip = new LabelNode();
        InsnList il = new InsnList();
        switch (choose(type)) {
            case 0 -> {
                // x * (x + 1) is always even -> low bit == 0 (holds under two's-complement overflow)
                int x = ThreadLocalRandom.current().nextInt();
                long v = (long) x * ((long) x + 1L);
                il.add(new LdcInsnNode(v));
                il.add(new LdcInsnNode(1L));
                il.add(new InsnNode(Opcodes.LAND));
                il.add(new InsnNode(Opcodes.LCONST_0));
                il.add(new InsnNode(Opcodes.LCMP));
                il.add(new JumpInsnNode(Opcodes.IFEQ, skip));
            }
            case 1 -> {
                // Runtime.availableProcessors() > 0 -> always true
                il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                        "()Ljava/lang/Runtime;", false));
                il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "availableProcessors",
                        "()I", false));
                il.add(new InsnNode(Opcodes.ICONST_0));
                il.add(new JumpInsnNode(Opcodes.IF_ICMPGT, skip));
            }
            default -> {
                // (x | 1) != 0 for any x -> always true (low bit forced to 1)
                int x = ThreadLocalRandom.current().nextInt();
                il.add(new LdcInsnNode(x));
                il.add(new InsnNode(Opcodes.ICONST_1));
                il.add(new InsnNode(Opcodes.IOR));
                il.add(new JumpInsnNode(Opcodes.IFNE, skip));
            }
        }
        // Unreachable throw so verifier is happy
        il.add(new InsnNode(Opcodes.ACONST_NULL));
        il.add(new InsnNode(Opcodes.ATHROW));
        il.add(skip);
        mn.instructions.insertBefore(point, il);
        return true;
    }

    private int choose(ObfuscatorConfig.OpaqueType type) {
        return switch (type) {
            case MATH -> 0;
            case RUNTIME -> 1;
            case MIXED -> ThreadLocalRandom.current().nextInt(3);
        };
    }
}
