package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
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
 * Rewrites call sites into {@code invokedynamic} backed by a per-class
 * bootstrap that resolves the target at link time via reflective lookup of
 * encrypted owner/name/descriptor strings.
 *
 * <p>Only calls whose owner is another class in our own {@link ClassPool} are
 * wrapped — this guarantees the method is resolvable and lets us handle any
 * rename atomically. Calls into {@code java.*}, {@code org.bukkit.*}, etc.
 * are left alone.
 *
 * <p>The bootstrap is a private static method on each transformed class. It
 * uses the receiving class's own {@link java.lang.invoke.MethodHandles.Lookup},
 * which has full access to private members and the same public visibility as
 * any other caller.
 */
public class IndyCallTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(IndyCallTransformer.class);

    private static final String BSM_PREFIX = "$obfIC";
    private static final String DEC_PREFIX = "$obfICd";
    private static final String BSM_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)"
                    + "Ljava/lang/invoke/CallSite;";

    // Simple LCG-style rolling XOR for owner/name/desc.
    private static final int INDY_KEY = 0x5A17C0DE;

    /**
     * Deterministic per-class 8-character alphanumeric suffix so each
     * class's bootstrap method and decoder helper have a unique name.
     * Defeats grep-based recovery of every indy bootstrap in the JAR.
     */
    private static String classSuffix(String internalName) {
        long h = 0xCBF29CE484222325L;
        for (int i = 0; i < internalName.length(); i++) {
            h ^= internalName.charAt(i);
            h *= 0x100000001B3L;
        }
        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        char[] out = new char[8];
        for (int i = 0; i < out.length; i++) {
            out[i] = alphabet[(int) ((h >>> (i * 8)) & 0x3F) % alphabet.length];
            h = (h ^ (h >>> 7)) * 0xBF58476D1CE4E5B9L;
        }
        return new String(out);
    }

    @Override
    public String name() {
        return "indy-call";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int rewritten = 0;
        int classesTouched = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ("module-info".equals(cn.name)) continue;
            // The BSM Handle below is emitted with isInterface=false,
            // which in an interface class would produce a
            // CONSTANT_Methodref_info in the constant pool instead of
            // the CONSTANT_InterfaceMethodRef_info the JVM requires.
            // That triggers BootstrapMethodError /
            // IncompatibleClassChangeError at link time. Interfaces
            // host too few call sites to be worth a second code path,
            // so we skip them.
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_MODULE)) != 0) continue;
            String suffix = classSuffix(cn.name);
            String bsmName = BSM_PREFIX + suffix;
            String decName = DEC_PREFIX + suffix;
            int perClass = 0;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (bsmName.equals(mn.name) || decName.equals(mn.name)) continue;
                perClass += rewriteMethod(cn, mn, pool, bsmName, decName);
            }
            if (perClass > 0) {
                injectBootstrap(cn, bsmName, decName);
                classesTouched++;
                rewritten += perClass;
            }
        }
        if (rewritten > 0) {
            log.info("Rewrote {} call sites as invokedynamic across {} classes",
                    rewritten, classesTouched);
        } else {
            log.info("No eligible call sites for indy rewrite");
        }
    }

    private int rewriteMethod(ClassNode cn, MethodNode mn, ClassPool pool, String bsmName, String decName) {
        List<MethodInsnNode> targets = new ArrayList<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof MethodInsnNode min)) continue;
            if (min.name.startsWith("<")) continue;
            if (bsmName.equals(min.name) || decName.equals(min.name)) continue;
            int op = min.getOpcode();
            if (op != Opcodes.INVOKESTATIC && op != Opcodes.INVOKEVIRTUAL
                    && op != Opcodes.INVOKEINTERFACE) {
                continue;
            }
            if (!pool.containsClass(min.owner)) continue;
            targets.add(min);
        }
        for (MethodInsnNode min : targets) {
            int op = min.getOpcode();
            int kind = switch (op) {
                case Opcodes.INVOKESTATIC -> 0;
                case Opcodes.INVOKEVIRTUAL -> 1;
                case Opcodes.INVOKEINTERFACE -> 2;
                default -> -1;
            };
            if (kind < 0) continue;
            String indyDesc = (op == Opcodes.INVOKESTATIC)
                    ? min.desc
                    : "(L" + min.owner + ";" + min.desc.substring(1);
            Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, cn.name, bsmName, BSM_DESC, false);
            InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(
                    "m",
                    indyDesc,
                    bsm,
                    encrypt(min.owner),
                    encrypt(min.name),
                    encrypt(min.desc),
                    Integer.valueOf(kind)
            );
            mn.instructions.set(min, indy);
        }
        return targets.size();
    }

    private static String encrypt(String plaintext) {
        byte[] src = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] out = new byte[src.length];
        int k = INDY_KEY;
        for (int i = 0; i < src.length; i++) {
            out[i] = (byte) (src[i] ^ (k & 0xFF));
            k = k * 0x45D9F3B + 0x119DE1F3;
        }
        return java.util.Base64.getEncoder().encodeToString(out);
    }

    private void injectBootstrap(ClassNode cn, String bsmName, String decName) {
        boolean hasBsm = false;
        boolean hasDec = false;
        for (MethodNode m : cn.methods) {
            if (bsmName.equals(m.name) && BSM_DESC.equals(m.desc)) hasBsm = true;
            if (decName.equals(m.name)) hasDec = true;
        }
        if (!hasDec) cn.methods.add(buildDecoder(cn, decName));
        if (!hasBsm) cn.methods.add(buildBsm(cn, bsmName, decName));
    }

    /**
     * Decoder helper: decrypts Base64/XOR-obfuscated UTF-8 strings used in BSM
     * args. Kept separate so COMPUTE_FRAMES can analyze each method without
     * cross-method type dependencies.
     */
    private MethodNode buildDecoder(ClassNode cn, String decName) {
        MethodNode m = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                decName,
                "(Ljava/lang/String;)Ljava/lang/String;",
                null,
                null
        );
        InsnList il = m.instructions;
        LabelNode loop = new LabelNode();
        LabelNode loopEnd = new LabelNode();

        // byte[] raw = Base64.getDecoder().decode(arg0)
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64",
                "getDecoder", "()Ljava/util/Base64$Decoder;", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder",
                "decode", "(Ljava/lang/String;)[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 1));
        // byte[] out = new byte[raw.length]
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));
        // int k = INDY_KEY
        il.add(new LdcInsnNode(Integer.valueOf(INDY_KEY)));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));
        // int i = 0
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, 4));

        il.add(loop);
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new InsnNode(Opcodes.BALOAD));
        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
        il.add(new InsnNode(Opcodes.IAND));
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new InsnNode(Opcodes.I2B));
        il.add(new InsnNode(Opcodes.BASTORE));

        il.add(new VarInsnNode(Opcodes.ILOAD, 3));
        il.add(new LdcInsnNode(Integer.valueOf(0x45D9F3B)));
        il.add(new InsnNode(Opcodes.IMUL));
        il.add(new LdcInsnNode(Integer.valueOf(0x119DE1F3)));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));

        il.add(new IincInsnNode(4, 1));
        il.add(new JumpInsnNode(Opcodes.GOTO, loop));

        il.add(loopEnd);
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new FieldInsnNode(Opcodes.GETSTATIC,
                "java/nio/charset/StandardCharsets", "UTF_8",
                "Ljava/nio/charset/Charset;"));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String",
                "<init>", "([BLjava/nio/charset/Charset;)V", false));
        il.add(new InsnNode(Opcodes.ARETURN));

        m.maxLocals = 5;
        m.maxStack = 5;
        return m;
    }

    /**
     * Bootstrap method: reads [ownerEnc, nameEnc, descEnc, kind] from the
     * BSM args, decrypts them, resolves a method handle via
     * {@link java.lang.invoke.MethodHandles.Lookup#findStatic findStatic} or
     * {@link java.lang.invoke.MethodHandles.Lookup#findVirtual findVirtual},
     * and wraps it in a {@link java.lang.invoke.ConstantCallSite} adapted to
     * the call-site {@code MethodType}.
     *
     * <p>Layout matches the standard {@code if (kind == 0) findStatic else
     * findVirtual} shape in source form so the verifier's stack-map check
     * sees a clean join at {@code merge:} with a single operand slot on the
     * stack (the resolved MethodHandle).
     */
    private MethodNode buildBsm(ClassNode cn, String bsmName, String decName) {
        MethodNode m = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                bsmName,
                BSM_DESC,
                null,
                new String[]{"java/lang/Throwable"}
        );

        int L_LOOKUP = 0, L_NAME = 1, L_TYPE = 2, L_ARGS = 3;
        int L_OWNER = 4, L_NAMESTR = 5, L_DESC = 6, L_KIND = 7;
        int L_CLS = 8, L_MT = 9;

        InsnList il = m.instructions;

        // ownerStr = $obfICd((String) args[0])
        il.add(new VarInsnNode(Opcodes.ALOAD, L_ARGS));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new InsnNode(Opcodes.AALOAD));
        il.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decName,
                "(Ljava/lang/String;)Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_OWNER));

        // nameStr = $obfICd((String) args[1])
        il.add(new VarInsnNode(Opcodes.ALOAD, L_ARGS));
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new InsnNode(Opcodes.AALOAD));
        il.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decName,
                "(Ljava/lang/String;)Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_NAMESTR));

        // descStr = $obfICd((String) args[2])
        il.add(new VarInsnNode(Opcodes.ALOAD, L_ARGS));
        il.add(new InsnNode(Opcodes.ICONST_2));
        il.add(new InsnNode(Opcodes.AALOAD));
        il.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, decName,
                "(Ljava/lang/String;)Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_DESC));

        // kind = ((Integer) args[3]).intValue()
        il.add(new VarInsnNode(Opcodes.ALOAD, L_ARGS));
        il.add(new InsnNode(Opcodes.ICONST_3));
        il.add(new InsnNode(Opcodes.AALOAD));
        il.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer",
                "intValue", "()I", false));
        il.add(new VarInsnNode(Opcodes.ISTORE, L_KIND));

        // cls = Class.forName(ownerStr.replace('/','.'), false, lookup.lookupClass().getClassLoader())
        il.add(new VarInsnNode(Opcodes.ALOAD, L_OWNER));
        il.add(new IntInsnNode(Opcodes.BIPUSH, '/'));
        il.add(new IntInsnNode(Opcodes.BIPUSH, '.'));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "replace",
                "(CC)Ljava/lang/String;", false));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_LOOKUP));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", "lookupClass",
                "()Ljava/lang/Class;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class",
                "getClassLoader", "()Ljava/lang/ClassLoader;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Class",
                "forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;",
                false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_CLS));

        // mt = MethodType.fromMethodDescriptorString(descStr, cls.getClassLoader())
        il.add(new VarInsnNode(Opcodes.ALOAD, L_DESC));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_CLS));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class",
                "getClassLoader", "()Ljava/lang/ClassLoader;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/invoke/MethodType", "fromMethodDescriptorString",
                "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/invoke/MethodType;",
                false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_MT));

        // Standard if-else emitting MethodHandle on the stack at merge:
        //   if (kind != 0) { lookup.findVirtual(...) } else { lookup.findStatic(...) }
        LabelNode elseLbl = new LabelNode();
        LabelNode merge = new LabelNode();

        il.add(new VarInsnNode(Opcodes.ILOAD, L_KIND));
        il.add(new JumpInsnNode(Opcodes.IFEQ, elseLbl));
        // then: findVirtual
        il.add(new VarInsnNode(Opcodes.ALOAD, L_LOOKUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_CLS));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_NAMESTR));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_MT));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", "findVirtual",
                "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;",
                false));
        il.add(new JumpInsnNode(Opcodes.GOTO, merge));
        // else: findStatic
        il.add(elseLbl);
        il.add(new VarInsnNode(Opcodes.ALOAD, L_LOOKUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_CLS));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_NAMESTR));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_MT));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", "findStatic",
                "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;",
                false));
        il.add(merge);
        // stack: [MethodHandle]
        // return new ConstantCallSite(mh.asType(type))
        il.add(new VarInsnNode(Opcodes.ALOAD, L_TYPE));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandle", "asType",
                "(Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;",
                false));
        // stack: [MethodHandle adapted]
        // wrap in ConstantCallSite
        il.add(new VarInsnNode(Opcodes.ASTORE, L_MT)); // reuse L_MT as MH holder (already unused)
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/invoke/ConstantCallSite"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_MT));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/invoke/ConstantCallSite", "<init>",
                "(Ljava/lang/invoke/MethodHandle;)V", false));
        il.add(new InsnNode(Opcodes.ARETURN));

        m.maxLocals = 10;
        m.maxStack = 6;
        return m;
    }
}
