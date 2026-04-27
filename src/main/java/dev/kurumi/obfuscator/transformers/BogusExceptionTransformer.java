package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps each non-trivial method body in a dummy try/catch block whose handler
 * is unreachable at runtime but present in the bytecode.
 */
public class BogusExceptionTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(BogusExceptionTransformer.class);

    @Override
    public String name() {
        return "bogus-exception";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int modified = 0;
        final String pfx = SyntheticNaming.prefix(pool);
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) continue;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() < 2) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.startsWith(pfx)) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;

                if (wrap(mn)) modified++;
            }
        }
        log.info("Bogus-exception-wrapped {} methods", modified);
    }

    private boolean wrap(MethodNode mn) {
        InsnList il = mn.instructions;
        LabelNode begin = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();

        // Prefix: begin label, opaque-true guard (0 != 1 -> skip)
        InsnList prefix = new InsnList();
        prefix.add(begin);
        prefix.add(new LdcInsnNode(0));
        prefix.add(new LdcInsnNode(1));
        LabelNode after = new LabelNode();
        prefix.add(new JumpInsnNode(Opcodes.IF_ICMPNE, after));
        // unreachable: throw
        prefix.add(new InsnNode(Opcodes.ACONST_NULL));
        prefix.add(new InsnNode(Opcodes.ATHROW));
        prefix.add(after);
        il.insertBefore(il.getFirst(), prefix);

        // Suffix: end label + handler that rethrows the caught exception.
        // Rethrow guarantees the bytecode still terminates validly after the
        // original method body's return has already executed.
        InsnList suffix = new InsnList();
        suffix.add(end);
        suffix.add(handler);
        suffix.add(new InsnNode(Opcodes.ATHROW));
        il.add(suffix);

        mn.tryCatchBlocks.add(new TryCatchBlockNode(begin, end, handler, "java/lang/Throwable"));
        return true;
    }
}
