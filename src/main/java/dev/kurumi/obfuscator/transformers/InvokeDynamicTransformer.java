package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Converts plain {@code INVOKESTATIC} calls to non-lambda helpers into
 * {@code INVOKEDYNAMIC} with a custom bootstrap method so static analysis
 * cannot resolve the target class directly.
 * <p>
 * Disabled by default: the lambda-guard auto-detects {@code LambdaMetafactory}
 * usage in the JAR and declines to run if any is found.
 */
public class InvokeDynamicTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(InvokeDynamicTransformer.class);

    private static final String BSM_SUFFIX = "Bootstrap";
    private static final String BSM_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;";

    @Override
    public String name() {
        return "invokedynamic";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        if (ctx.config().invokeDynamicAutoDetectLambdas() && containsLambda(pool)) {
            log.info("Skipping invokedynamic: lambdas detected in input JAR");
            return;
        }
        int converted = 0;
        final String pfx = SyntheticNaming.prefix(pool);
        final String bsmName = pfx + BSM_SUFFIX;
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) continue;
            boolean anyInCn = false;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                if (mn.name.equals(bsmName)) continue;
                if (mn.name.startsWith("<")) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (insn.getOpcode() == Opcodes.INVOKESTATIC && insn instanceof MethodInsnNode m) {
                        if (m.name.startsWith(pfx)) continue;
                        if (m.owner.startsWith("java/lang/invoke/")) continue;
                        Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, cn.name, bsmName, BSM_DESC, false);
                        InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(
                                m.name + "|" + m.owner,
                                m.desc,
                                bsm);
                        mn.instructions.set(m, indy);
                        anyInCn = true;
                        converted++;
                    }
                }
            }
            if (anyInCn) injectBootstrap(cn, bsmName);
        }
        log.info("Converted {} invokestatic->invokedynamic", converted);
    }

    private boolean containsLambda(ClassPool pool) {
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (insn instanceof InvokeDynamicInsnNode indy) {
                        if (indy.bsm != null && indy.bsm.getOwner().contains("LambdaMetafactory")) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private void injectBootstrap(ClassNode cn, String bsmName) {
        for (MethodNode existing : cn.methods) {
            if (existing.name.equals(bsmName) && existing.desc.equals(BSM_DESC)) return;
        }
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                bsmName, BSM_DESC, null,
                new String[]{"java/lang/Throwable"});
        InsnList il = new InsnList();
        // Parse name ("method|owner") and resolve
        // int sep = name.indexOf('|');
        // String methodName = name.substring(0, sep);
        // String owner = name.substring(sep + 1).replace('/', '.'); // already internal slash form, fix separator
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new LdcInsnNode("\\|"));
        il.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, 2));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "split",
                "(Ljava/lang/String;I)[Ljava/lang/String;", false));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ASTORE, 3));

        // Class target = Class.forName(parts[1].replace('/', '.'));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 3));
        il.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_1));
        il.add(new org.objectweb.asm.tree.InsnNode(Opcodes.AALOAD));
        il.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, '/'));
        il.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, '.'));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "replace",
                "(CC)Ljava/lang/String;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ASTORE, 4));

        // MethodHandle mh = lookup.findStatic(target, parts[0], type);
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 4));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 3));
        il.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ICONST_0));
        il.add(new org.objectweb.asm.tree.InsnNode(Opcodes.AALOAD));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findStatic",
                "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ASTORE, 5));

        // return new ConstantCallSite(mh);
        il.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.NEW, "java/lang/invoke/ConstantCallSite"));
        il.add(new org.objectweb.asm.tree.InsnNode(Opcodes.DUP));
        il.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 5));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/invoke/ConstantCallSite", "<init>",
                "(Ljava/lang/invoke/MethodHandle;)V", false));
        il.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ARETURN));
        mn.instructions = il;
        cn.methods.add(mn);
        // keep a FieldNode reference so stripping doesn't eliminate the method
        if (false) new FieldNode(0, null, null, null, null);
    }
}
