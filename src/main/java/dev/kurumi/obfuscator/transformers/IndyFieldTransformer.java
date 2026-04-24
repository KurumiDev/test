package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
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
 * Rewrites field-access bytecodes into {@code invokedynamic}, backed by a
 * per-class bootstrap that resolves the target field at link time via
 * reflective lookup of encrypted owner/name/descriptor strings.
 *
 * <p>This is the field-access analog of {@link IndyCallTransformer}. After
 * this transformer runs, the original class no longer contains
 * {@code GETFIELD}/{@code PUTFIELD}/{@code GETSTATIC}/{@code PUTSTATIC}
 * bytecodes for pool-owned fields; every such access is rewritten to an
 * {@code invokedynamic} instruction whose constant-pool entry stores only
 * encrypted strings. A static analyzer cannot see which field is being
 * read/written without evaluating the bootstrap at link time, which in
 * turn requires the runtime-bound class-identity hash the decoder uses.
 *
 * <p>Supported kinds:
 * <ul>
 *   <li>0 &mdash; {@code GETSTATIC} &rarr; {@code findStaticGetter}</li>
 *   <li>1 &mdash; {@code PUTSTATIC} &rarr; {@code findStaticSetter}</li>
 *   <li>2 &mdash; {@code GETFIELD}  &rarr; {@code findGetter}</li>
 *   <li>3 &mdash; {@code PUTFIELD}  &rarr; {@code findSetter}</li>
 * </ul>
 *
 * <p>Skipped sites:
 * <ul>
 *   <li>Field accesses whose owner is not in our owned {@link ClassPool}
 *       (e.g. {@code java.lang.System.out}).</li>
 *   <li>Synthetic fields our own obfuscation created ({@code $obf*},
 *       {@code SEED}).</li>
 *   <li>{@code PUTFIELD}/{@code PUTSTATIC} on {@code final} fields &mdash;
 *       {@code MethodHandles.Lookup#findSetter} rejects these even with
 *       {@code privateLookupIn}.</li>
 *   <li>All {@code <init>} and {@code <clinit>} bodies &mdash; touching
 *       final fields during construction/class-init via method handles
 *       is either disallowed or produces circular-init risk.</li>
 * </ul>
 *
 * <p>The BSM uses
 * {@link java.lang.invoke.MethodHandles#privateLookupIn
 * MethodHandles.privateLookupIn} to obtain a full-access lookup into the
 * field's owner class, so package-private and private fields on other
 * pool classes are still reachable. This keeps existing encapsulation
 * invariant after the rewrite (no visibility elevation required).
 */
public class IndyFieldTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(IndyFieldTransformer.class);

    private static final String BSM_PREFIX = "$obfIF";
    private static final String DEC_PREFIX = "$obfIFd";
    private static final String BSM_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)"
                    + "Ljava/lang/invoke/CallSite;";

    // Distinct from IndyCallTransformer.INDY_KEY so a reverser who
    // reconstructs one decoder cannot reuse it against the other.
    private static final int INDY_KEY = 0x2F8B1CAF;

    @Override
    public String name() {
        return "indy-field";
    }

    @Override
    public boolean isEnabled(ObfuscatorConfig config) {
        return config.isTransformerEnabled("indy-field");
    }

    /**
     * Per-class alphanumeric suffix, same scheme as IndyCallTransformer
     * but with a different starting salt so the two do not collide
     * nor look related to casual pattern matching.
     */
    private static String classSuffix(String internalName) {
        long h = 0x84222325CBF29CE4L;
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
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int rewritten = 0;
        int classesTouched = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ("module-info".equals(cn.name)) continue;
            String suffix = classSuffix(cn.name);
            String bsmName = BSM_PREFIX + suffix;
            String decName = DEC_PREFIX + suffix;
            int variant = DecoderPolymorphism.variantFor(cn.name);
            int perClass = 0;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                // Ctors and class-init touch final fields and may run
                // during bootstrap — leave them alone.
                if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) continue;
                if (bsmName.equals(mn.name) || decName.equals(mn.name)) continue;
                perClass += rewriteMethod(cn, mn, pool, bsmName, decName, variant);
            }
            if (perClass > 0) {
                injectBootstrap(cn, bsmName, decName, variant);
                classesTouched++;
                rewritten += perClass;
            }
        }
        if (rewritten > 0) {
            log.info("Rewrote {} field-access sites as invokedynamic across {} classes",
                    rewritten, classesTouched);
        } else {
            log.info("No eligible field-access sites for indy-field rewrite");
        }
    }

    private int rewriteMethod(ClassNode cn, MethodNode mn, ClassPool pool,
                              String bsmName, String decName, int variant) {
        List<FieldInsnNode> targets = new ArrayList<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof FieldInsnNode fin)) continue;
            int op = fin.getOpcode();
            if (op != Opcodes.GETFIELD && op != Opcodes.PUTFIELD
                    && op != Opcodes.GETSTATIC && op != Opcodes.PUTSTATIC) {
                continue;
            }
            if (!pool.containsClass(fin.owner)) continue;
            if (isSkippableField(fin.name)) continue;
            if (isFinalField(pool, fin)
                    && (op == Opcodes.PUTFIELD || op == Opcodes.PUTSTATIC)) {
                continue;
            }
            targets.add(fin);
        }
        for (FieldInsnNode fin : targets) {
            int op = fin.getOpcode();
            int kind = switch (op) {
                case Opcodes.GETSTATIC -> 0;
                case Opcodes.PUTSTATIC -> 1;
                case Opcodes.GETFIELD -> 2;
                case Opcodes.PUTFIELD -> 3;
                default -> -1;
            };
            if (kind < 0) continue;
            String bsmCallName = (kind == 0 || kind == 2) ? "g" : "s";
            String indyDesc = indyDescFor(op, fin);
            Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, cn.name,
                    bsmName, BSM_DESC, false);
            InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(
                    bsmCallName,
                    indyDesc,
                    bsm,
                    encrypt(fin.owner, variant),
                    encrypt(fin.name, variant),
                    encrypt(fin.desc, variant),
                    Integer.valueOf(kind)
            );
            mn.instructions.set(fin, indy);
        }
        return targets.size();
    }

    private static String indyDescFor(int op, FieldInsnNode fin) {
        // GETSTATIC foo:T         -> ()T
        // PUTSTATIC foo:T         -> (T)V
        // GETFIELD  foo:T on O    -> (LO;)T
        // PUTFIELD  foo:T on O    -> (LO;T)V
        return switch (op) {
            case Opcodes.GETSTATIC -> "()" + fin.desc;
            case Opcodes.PUTSTATIC -> "(" + fin.desc + ")V";
            case Opcodes.GETFIELD -> "(L" + fin.owner + ";)" + fin.desc;
            case Opcodes.PUTFIELD -> "(L" + fin.owner + ";" + fin.desc + ")V";
            default -> throw new IllegalStateException("bad op " + op);
        };
    }

    private static boolean isSkippableField(String name) {
        // Our own synthetic fields. Leave them alone.
        if (name.startsWith("$obf")) return true;
        if ("SEED".equals(name)) return true;
        return false;
    }

    private static boolean isFinalField(ClassPool pool, FieldInsnNode fin) {
        ClassNode owner = pool.find(fin.owner);
        if (owner == null || owner.fields == null) return false;
        for (FieldNode f : owner.fields) {
            if (fin.name.equals(f.name) && fin.desc.equals(f.desc)) {
                return (f.access & Opcodes.ACC_FINAL) != 0;
            }
        }
        return false;
    }

    private static String encrypt(String plaintext, int variant) {
        byte[] src = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] out = DecoderPolymorphism.xorByteStream(src, INDY_KEY, variant);
        return java.util.Base64.getEncoder().encodeToString(out);
    }

    private void injectBootstrap(ClassNode cn, String bsmName, String decName, int variant) {
        boolean hasBsm = false;
        boolean hasDec = false;
        for (MethodNode m : cn.methods) {
            if (bsmName.equals(m.name) && BSM_DESC.equals(m.desc)) hasBsm = true;
            if (decName.equals(m.name)) hasDec = true;
        }
        if (!hasDec) cn.methods.add(buildDecoder(cn, decName, variant));
        if (!hasBsm) cn.methods.add(buildBsm(cn, bsmName, decName));
    }

    /**
     * Decoder helper: decrypts Base64/XOR-obfuscated UTF-8 strings used
     * in BSM args. Mirrors {@link IndyCallTransformer}'s decoder but
     * keyed off {@link #INDY_KEY} so copying one helper into an
     * external probe tool does not decrypt the other.
     */
    private MethodNode buildDecoder(ClassNode cn, String decName, int variant) {
        MethodNode m = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                decName,
                "(Ljava/lang/String;)Ljava/lang/String;",
                null,
                null
        );
        // slots: 0=arg, 1=raw, 2=out, 3=k, 4=i, 5=plain(int)
        InsnList il = m.instructions;
        LabelNode loop = new LabelNode();
        LabelNode loopEnd = new LabelNode();

        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Base64",
                "getDecoder", "()Ljava/util/Base64$Decoder;", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder",
                "decode", "(Ljava/lang/String;)[B", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, 1));
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));
        il.add(new LdcInsnNode(Integer.valueOf(INDY_KEY)));
        il.add(new VarInsnNode(Opcodes.ISTORE, 3));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new VarInsnNode(Opcodes.ISTORE, 4));

        il.add(loop);
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new InsnNode(Opcodes.ARRAYLENGTH));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));

        // plain = (raw[i] & 0xFF) ^ mask(k, i)
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new InsnNode(Opcodes.BALOAD));
        il.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
        il.add(new InsnNode(Opcodes.IAND));
        DecoderPolymorphism.emitMask(il, 3, 4, variant);
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new VarInsnNode(Opcodes.ISTORE, 5));

        // out[i] = (byte) plain
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new VarInsnNode(Opcodes.ILOAD, 4));
        il.add(new VarInsnNode(Opcodes.ILOAD, 5));
        il.add(new InsnNode(Opcodes.I2B));
        il.add(new InsnNode(Opcodes.BASTORE));

        DecoderPolymorphism.emitKeyUpdate(il, 3, 4, 5, variant);

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

        m.maxLocals = 6;
        m.maxStack = 5;
        return m;
    }

    /**
     * Bootstrap: reads {@code [ownerEnc, fieldNameEnc, fieldDescEnc, kind]}
     * from the BSM args, decrypts them, gets a full-power lookup into the
     * field's owner class via {@code MethodHandles.privateLookupIn}, then
     * resolves the appropriate getter/setter method handle, adapts it to
     * the call-site type, and wraps it in a
     * {@link java.lang.invoke.ConstantCallSite ConstantCallSite}.
     *
     * <p>Layout is deliberately kept as a chain of {@code IFEQ}s rather
     * than a {@code TABLESWITCH} because each arm has a different arity
     * and return type &mdash; a switch would force COMPUTE_FRAMES to
     * merge four incompatible operand stacks at the end label.
     *
     * <pre>
     * if (kind == 0) mh = plookup.findStaticGetter(cls, name, ftype);
     * else if (kind == 1) mh = plookup.findStaticSetter(cls, name, ftype);
     * else if (kind == 2) mh = plookup.findGetter(cls, name, ftype);
     * else                mh = plookup.findSetter(cls, name, ftype);
     * return new ConstantCallSite(mh.asType(type));
     * </pre>
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
        int L_OWNER = 4, L_FIELDN = 5, L_FIELDD = 6, L_KIND = 7;
        int L_CLS = 8, L_FTYPE = 9, L_PLOOKUP = 10, L_MH = 11;

        InsnList il = m.instructions;

        // ownerStr = decode((String) args[0])
        loadArgString(il, L_ARGS, 0, cn.name, decName, L_OWNER);
        // fieldNameStr = decode((String) args[1])
        loadArgString(il, L_ARGS, 1, cn.name, decName, L_FIELDN);
        // fieldDescStr = decode((String) args[2])
        loadArgString(il, L_ARGS, 2, cn.name, decName, L_FIELDD);

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

        // ftype = MethodType.fromMethodDescriptorString("(" + fieldDescStr + ")V", cls.getClassLoader())
        //            .parameterType(0)
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/StringBuilder", "<init>", "()V", false));
        il.add(new LdcInsnNode("("));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_FIELDD));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        il.add(new LdcInsnNode(")V"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "append",
                "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/StringBuilder", "toString",
                "()Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_CLS));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class",
                "getClassLoader", "()Ljava/lang/ClassLoader;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/invoke/MethodType", "fromMethodDescriptorString",
                "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/invoke/MethodType;",
                false));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodType", "parameterType",
                "(I)Ljava/lang/Class;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_FTYPE));

        // plookup = MethodHandles.privateLookupIn(cls, lookup)
        il.add(new VarInsnNode(Opcodes.ALOAD, L_CLS));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_LOOKUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/invoke/MethodHandles", "privateLookupIn",
                "(Ljava/lang/Class;Ljava/lang/invoke/MethodHandles$Lookup;)"
                        + "Ljava/lang/invoke/MethodHandles$Lookup;",
                false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_PLOOKUP));

        // if-else chain on kind. Each arm stores a MethodHandle into L_MH.
        LabelNode notStaticGetter = new LabelNode();
        LabelNode notStaticSetter = new LabelNode();
        LabelNode notInstanceGetter = new LabelNode();
        LabelNode merge = new LabelNode();

        // if (kind != 0) goto notStaticGetter else findStaticGetter
        il.add(new VarInsnNode(Opcodes.ILOAD, L_KIND));
        il.add(new JumpInsnNode(Opcodes.IFNE, notStaticGetter));
        emitFindField(il, L_PLOOKUP, L_CLS, L_FIELDN, L_FTYPE, L_MH,
                "findStaticGetter");
        il.add(new JumpInsnNode(Opcodes.GOTO, merge));

        // if (kind != 1) goto notStaticSetter else findStaticSetter
        il.add(notStaticGetter);
        il.add(new VarInsnNode(Opcodes.ILOAD, L_KIND));
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPNE, notStaticSetter));
        emitFindField(il, L_PLOOKUP, L_CLS, L_FIELDN, L_FTYPE, L_MH,
                "findStaticSetter");
        il.add(new JumpInsnNode(Opcodes.GOTO, merge));

        // if (kind != 2) goto notInstanceGetter else findGetter
        il.add(notStaticSetter);
        il.add(new VarInsnNode(Opcodes.ILOAD, L_KIND));
        il.add(new InsnNode(Opcodes.ICONST_2));
        il.add(new JumpInsnNode(Opcodes.IF_ICMPNE, notInstanceGetter));
        emitFindField(il, L_PLOOKUP, L_CLS, L_FIELDN, L_FTYPE, L_MH,
                "findGetter");
        il.add(new JumpInsnNode(Opcodes.GOTO, merge));

        // else findSetter (kind == 3)
        il.add(notInstanceGetter);
        emitFindField(il, L_PLOOKUP, L_CLS, L_FIELDN, L_FTYPE, L_MH,
                "findSetter");

        il.add(merge);

        // return new ConstantCallSite(mh.asType(type))
        il.add(new VarInsnNode(Opcodes.ALOAD, L_MH));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_TYPE));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandle", "asType",
                "(Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;",
                false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_MH));

        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/invoke/ConstantCallSite"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_MH));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/invoke/ConstantCallSite", "<init>",
                "(Ljava/lang/invoke/MethodHandle;)V", false));
        il.add(new InsnNode(Opcodes.ARETURN));

        m.maxLocals = 12;
        m.maxStack = 6;
        return m;
    }

    private static void loadArgString(InsnList il, int L_ARGS, int idx,
                                      String ownerInternal, String decName,
                                      int storeSlot) {
        il.add(new VarInsnNode(Opcodes.ALOAD, L_ARGS));
        il.add(intConst(idx));
        il.add(new InsnNode(Opcodes.AALOAD));
        il.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC, ownerInternal, decName,
                "(Ljava/lang/String;)Ljava/lang/String;", false));
        il.add(new VarInsnNode(Opcodes.ASTORE, storeSlot));
    }

    private static AbstractInsnNode intConst(int i) {
        return switch (i) {
            case 0 -> new InsnNode(Opcodes.ICONST_0);
            case 1 -> new InsnNode(Opcodes.ICONST_1);
            case 2 -> new InsnNode(Opcodes.ICONST_2);
            case 3 -> new InsnNode(Opcodes.ICONST_3);
            case 4 -> new InsnNode(Opcodes.ICONST_4);
            case 5 -> new InsnNode(Opcodes.ICONST_5);
            default -> new IntInsnNode(Opcodes.BIPUSH, i);
        };
    }

    private static void emitFindField(InsnList il, int L_PLOOKUP, int L_CLS,
                                      int L_FIELDN, int L_FTYPE, int L_MH,
                                      String method) {
        il.add(new VarInsnNode(Opcodes.ALOAD, L_PLOOKUP));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_CLS));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_FIELDN));
        il.add(new VarInsnNode(Opcodes.ALOAD, L_FTYPE));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandles$Lookup", method,
                "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)"
                        + "Ljava/lang/invoke/MethodHandle;",
                false));
        il.add(new VarInsnNode(Opcodes.ASTORE, L_MH));
    }
}
