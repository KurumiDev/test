package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Replaces {@code LDC} class literals (e.g. {@code Foo.class}) with runtime
 * {@code Class.forName(String)} lookups. The class name string passes through
 * string-encryption later in the pipeline, so the plain FQN never lives in
 * the constant pool of the shipped JAR.
 *
 * <p>Each affected class grows a synthetic static helper:
 * <pre>
 *   private static Class&lt;?&gt; $obfCl(String name) {
 *       try { return Class.forName(name, false, MyClass.class.getClassLoader()); }
 *       catch (ClassNotFoundException e) { throw new NoClassDefFoundError(name); }
 *   }
 * </pre>
 *
 * <p>Skips primitive class literals (they are compiled as {@code GETSTATIC TYPE}
 * and never appear as {@code LDC Type}) and array class literals (Class.forName
 * format differs from descriptor; supported but gated behind {@link #ENABLE_ARRAYS}).
 */
public class ClassLiteralTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(ClassLiteralTransformer.class);

    private static final String HELPER_INFIX = "Cl";
    private static final String HELPER_DESC = "(Ljava/lang/String;)Ljava/lang/Class;";
    private static final boolean ENABLE_ARRAYS = true;

    /**
     * Per-class hashed helper name with a per-JAR prefix. The original
     * implementation used a fixed literal ({@code "$obfCl"}) so a
     * reverser could grep one symbol to find every class-literal helper
     * in the JAR <em>and</em> recognise the obfuscator from any sample.
     * Both the leading {@code $obf} and the trailing 6-char hash are now
     * polymorphic: prefix is per-JAR (different across different inputs)
     * and suffix is per-class within the JAR.
     */
    private static String helperName(String internalName, String prefix) {
        long h = 0xCBF29CE484222325L ^ 0xC1A55L;
        for (int i = 0; i < internalName.length(); i++) {
            h ^= internalName.charAt(i);
            h *= 0x100000001B3L;
        }
        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        StringBuilder sb = new StringBuilder(prefix).append(HELPER_INFIX);
        for (int i = 0; i < 6; i++) {
            sb.append(alphabet[(int) ((h >>> (i * 8)) & 0x3F) % alphabet.length]);
            h = (h ^ (h >>> 7)) * 0xBF58476D1CE4E5B9L;
        }
        return sb.toString();
    }

    @Override
    public String name() {
        return "class-literal";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int replaced = 0;
        int classesTouched = 0;
        final String pfx = SyntheticNaming.prefix(pool);
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) continue;

            String helperName = helperName(cn.name, pfx);
            boolean touched = false;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals(helperName)) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;

                List<LdcInsnNode> targets = new ArrayList<>();
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (insn.getOpcode() != Opcodes.LDC) continue;
                    if (!(insn instanceof LdcInsnNode ldc)) continue;
                    if (!(ldc.cst instanceof Type t)) continue;
                    if (t.getSort() == Type.METHOD) continue;
                    if (t.getSort() == Type.OBJECT) {
                        targets.add(ldc);
                    } else if (ENABLE_ARRAYS && t.getSort() == Type.ARRAY) {
                        targets.add(ldc);
                    }
                }

                for (LdcInsnNode ldc : targets) {
                    Type t = (Type) ldc.cst;
                    String runtimeName = forNameArgument(t);
                    if (runtimeName == null) continue;
                    InsnList il = new InsnList();
                    il.add(new LdcInsnNode(runtimeName));
                    il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name,
                            helperName, HELPER_DESC, false));
                    mn.instructions.insert(ldc, il);
                    mn.instructions.remove(ldc);
                    replaced++;
                    touched = true;
                }
            }

            if (touched) {
                injectHelper(cn, helperName);
                classesTouched++;
            }
        }
        log.info("Rewrote {} class literals across {} classes", replaced, classesTouched);
    }

    private static String forNameArgument(Type t) {
        if (t.getSort() == Type.OBJECT) {
            return t.getInternalName().replace('/', '.');
        }
        if (t.getSort() == Type.ARRAY) {
            // Class.forName understands "[Ljava.lang.String;" and "[[I"
            return t.getDescriptor().replace('/', '.');
        }
        return null;
    }

    private static void injectHelper(ClassNode cn, String helperName) {
        for (MethodNode m : cn.methods) {
            if (helperName.equals(m.name) && HELPER_DESC.equals(m.desc)) return;
        }
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                helperName, HELPER_DESC, null,
                new String[]{"java/lang/NoClassDefFoundError"});
        InsnList il = new InsnList();

        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();

        il.add(tryStart);
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false));
        il.add(tryEnd);
        il.add(new InsnNode(Opcodes.ARETURN));

        // catch (ClassNotFoundException e) -> throw new NoClassDefFoundError(name);
        il.add(handler);
        il.add(new VarInsnNode(Opcodes.ASTORE, 1));
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/NoClassDefFoundError"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/NoClassDefFoundError",
                "<init>", "(Ljava/lang/String;)V", false));
        il.add(new InsnNode(Opcodes.ATHROW));

        mn.instructions = il;
        mn.tryCatchBlocks = new ArrayList<>();
        mn.tryCatchBlocks.add(new TryCatchBlockNode(tryStart, tryEnd, handler,
                "java/lang/ClassNotFoundException"));
        mn.maxLocals = 2;
        mn.maxStack = 3;
        cn.methods.add(mn);
    }
}
