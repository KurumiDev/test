package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Expands {@code makeConcatWithConstants} invokedynamic call sites into an
 * explicit {@link StringBuilder} chain.
 *
 * <p>Why: Java 9+ compiles {@code "Hello " + x} to an {@code invokedynamic}
 * where the recipe string ({@code "Hello \u0001"}) lives as a bootstrap
 * argument in the constant pool — completely unencrypted. Expanding into a
 * StringBuilder chain moves those literals to plain {@code LDC} instructions
 * which the downstream {@link StringEncryptionTransformer} then encrypts.
 *
 * <p>This runs BEFORE {@code string-encryption} for exactly that reason.
 *
 * <p>Recipe format (JEP 280 / JDK-8086374):
 * <ul>
 *   <li>Regular UTF-16 codepoints are literal text.</li>
 *   <li>{@code \u0001} marks a dynamic argument slot (consumed from the stack).</li>
 *   <li>{@code \u0002} marks a literal constant slot (taken from BSM args).</li>
 * </ul>
 */
public class StringConcatTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(StringConcatTransformer.class);

    private static final String SCF = "java/lang/invoke/StringConcatFactory";
    private static final String MAKE_CONCAT_WC = "makeConcatWithConstants";
    private static final String SB = "java/lang/StringBuilder";

    @Override
    public String name() {
        return "string-concat";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int rewritten = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                rewritten += rewriteMethod(mn);
            }
        }
        if (rewritten > 0) log.info("Expanded {} makeConcatWithConstants call sites", rewritten);
        else log.info("No makeConcatWithConstants call sites found");
    }

    private int rewriteMethod(MethodNode mn) {
        int count = 0;
        List<InvokeDynamicInsnNode> targets = new ArrayList<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof InvokeDynamicInsnNode idn)) continue;
            Handle bsm = idn.bsm;
            if (bsm == null) continue;
            if (!SCF.equals(bsm.getOwner())) continue;
            if (!MAKE_CONCAT_WC.equals(bsm.getName())) continue;
            if (idn.bsmArgs.length < 1 || !(idn.bsmArgs[0] instanceof String)) continue;
            targets.add(idn);
        }
        for (InvokeDynamicInsnNode idn : targets) {
            if (expandOne(mn, idn)) count++;
        }
        return count;
    }

    private boolean expandOne(MethodNode mn, InvokeDynamicInsnNode idn) {
        String recipe = (String) idn.bsmArgs[0];
        Object[] literalConsts = new Object[idn.bsmArgs.length - 1];
        System.arraycopy(idn.bsmArgs, 1, literalConsts, 0, literalConsts.length);

        Type methodType = Type.getMethodType(idn.desc);
        Type[] argTypes = methodType.getArgumentTypes();
        Type retType = methodType.getReturnType();
        if (!retType.equals(Type.getType("Ljava/lang/String;"))) return false;

        // Allocate fresh local slots for spilled dynamic args. Start after the
        // current maxLocals, bump maxLocals accordingly.
        int firstSpillSlot = Math.max(mn.maxLocals, 1);
        int[] spillSlots = new int[argTypes.length];
        int slotCursor = firstSpillSlot;
        for (int i = 0; i < argTypes.length; i++) {
            spillSlots[i] = slotCursor;
            slotCursor += argTypes[i].getSize();
        }
        int newMaxLocals = slotCursor;

        InsnList replacement = new InsnList();
        // Spill dynamic args from stack (last arg is on top) into locals.
        for (int i = argTypes.length - 1; i >= 0; i--) {
            replacement.add(new VarInsnNode(argTypes[i].getOpcode(Opcodes.ISTORE), spillSlots[i]));
        }

        // new StringBuilder().
        replacement.add(new TypeInsnNode(Opcodes.NEW, SB));
        replacement.add(new InsnNode(Opcodes.DUP));
        replacement.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, SB, "<init>", "()V", false));

        int dynIdx = 0;
        int litIdx = 0;
        StringBuilder literalBuf = new StringBuilder();
        for (int i = 0; i < recipe.length(); i++) {
            char c = recipe.charAt(i);
            if (c == '\u0001') {
                flushLiteral(replacement, literalBuf);
                Type argType = argTypes[dynIdx];
                replacement.add(new VarInsnNode(argType.getOpcode(Opcodes.ILOAD), spillSlots[dynIdx]));
                replacement.add(appendCall(argType));
                dynIdx++;
            } else if (c == '\u0002') {
                flushLiteral(replacement, literalBuf);
                Object constant = literalConsts[litIdx++];
                appendConstant(replacement, constant);
            } else {
                literalBuf.append(c);
            }
        }
        flushLiteral(replacement, literalBuf);

        // .toString()
        replacement.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "toString",
                "()Ljava/lang/String;", false));

        mn.instructions.insert(idn, replacement);
        mn.instructions.remove(idn);
        mn.maxLocals = newMaxLocals;
        return true;
    }

    private static void flushLiteral(InsnList il, StringBuilder buf) {
        if (buf.length() == 0) return;
        il.add(new LdcInsnNode(buf.toString()));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        buf.setLength(0);
    }

    private static void appendConstant(InsnList il, Object cst) {
        if (cst instanceof String s) {
            il.add(new LdcInsnNode(s));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Integer i) {
            il.add(new LdcInsnNode(i));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append",
                    "(I)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Long l) {
            il.add(new LdcInsnNode(l));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append",
                    "(J)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Float f) {
            il.add(new LdcInsnNode(f));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append",
                    "(F)Ljava/lang/StringBuilder;", false));
        } else if (cst instanceof Double d) {
            il.add(new LdcInsnNode(d));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append",
                    "(D)Ljava/lang/StringBuilder;", false));
        } else {
            // Fallback: treat as Object
            il.add(new LdcInsnNode(String.valueOf(cst)));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        }
    }

    private static MethodInsnNode appendCall(Type t) {
        String desc = switch (t.getSort()) {
            case Type.BOOLEAN -> "(Z)Ljava/lang/StringBuilder;";
            case Type.CHAR -> "(C)Ljava/lang/StringBuilder;";
            case Type.BYTE, Type.SHORT, Type.INT -> "(I)Ljava/lang/StringBuilder;";
            case Type.LONG -> "(J)Ljava/lang/StringBuilder;";
            case Type.FLOAT -> "(F)Ljava/lang/StringBuilder;";
            case Type.DOUBLE -> "(D)Ljava/lang/StringBuilder;";
            case Type.OBJECT, Type.ARRAY -> {
                if ("Ljava/lang/String;".equals(t.getDescriptor())) {
                    yield "(Ljava/lang/String;)Ljava/lang/StringBuilder;";
                } else if ("Ljava/lang/CharSequence;".equals(t.getDescriptor())) {
                    yield "(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;";
                } else {
                    yield "(Ljava/lang/Object;)Ljava/lang/StringBuilder;";
                }
            }
            default -> "(Ljava/lang/Object;)Ljava/lang/StringBuilder;";
        };
        return new MethodInsnNode(Opcodes.INVOKEVIRTUAL, SB, "append", desc, false);
    }
}
