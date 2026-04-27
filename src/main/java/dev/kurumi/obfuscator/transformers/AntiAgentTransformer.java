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
 * Runtime detection of attached debuggers, JVMTI/native agents, and
 * Java instrumentation agents (Recaf, Threadtear, ByteBuddy debug,
 * arbitrary {@code -javaagent:} payloads).
 *
 * <p>Emits a synthetic guard class with a single {@code check()} entry
 * point. {@code check()} reads the JVM's input arguments via
 * {@link java.lang.management.ManagementFactory#getRuntimeMXBean()
 * .getInputArguments()} and matches any of the well-known suspicious
 * prefixes:
 * <ul>
 *   <li>{@code -agentlib:jdwp} &mdash; native JDWP debugger.</li>
 *   <li>{@code -Xrunjdwp} &mdash; legacy JDWP form.</li>
 *   <li>{@code -Xdebug} &mdash; legacy debug switch (often paired with
 *       {@code -Xrunjdwp}).</li>
 *   <li>{@code -javaagent:} &mdash; ANY Java agent (Recaf-CLI,
 *       Threadtear, ByteBuddy debug, custom instrumentation).</li>
 *   <li>{@code -agentpath:} &mdash; native JVMTI agents (heap dumpers,
 *       profilers, custom JNI hooks).</li>
 * </ul>
 *
 * <p>On any match, calls {@link Runtime#halt(int)} with status zero so
 * the JVM exits silently and the operator can't tell whether the
 * application succeeded or refused to run; nothing in stderr hints at
 * the obfuscator's involvement.
 *
 * <p>The guard caches its result in a {@code volatile boolean} so
 * subsequent invocations are a constant-time field read. Every
 * non-exempt user class gets a single call to the guard prepended to
 * its {@code <clinit>}; any one of them is enough to gate execution.
 *
 * <p>This transformer runs <b>before</b> the renamer so the synthetic
 * class participates in renaming, before string-encryption so the
 * comparison literals get encrypted alongside everything else, and
 * before flow-obfuscation so the loop+jump structure inside
 * {@code check()} gets distorted by every later mutation pass. The
 * guard's user-facing entry name uses the per-JAR synthetic prefix
 * from {@link SyntheticNaming} so cross-JAR fingerprinting on the
 * literal {@code Kurumi$AgentGuard} is impossible.
 */
public class AntiAgentTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(AntiAgentTransformer.class);

    private static final String GUARD_INFIX = "AgentGuard_";
    private static final String CHECK_NAME = "check";
    private static final String FLAG_NAME = "checked";

    @Override
    public String name() {
        return "anti-agent";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        String prefix = SyntheticNaming.prefix(pool);
        String guardName = prefix + GUARD_INFIX + Integer.toHexString(pool.size() ^ 0x7E517A05);

        ClassNode guard = buildGuardClass(guardName);
        pool.addClass(guard);

        int instrumented = 0;
        List<ClassNode> snapshot = new ArrayList<>(pool.allClassNodes());
        for (ClassNode cn : snapshot) {
            if (cn == guard) continue;
            if (cn.name.equals(guardName)) continue;
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
            if ((cn.access & Opcodes.ACC_ANNOTATION) != 0) continue;
            if ((cn.access & Opcodes.ACC_MODULE) != 0) continue;
            // skip classes that participate in vault decryption — they
            // run before the guard would be loadable.
            if (cn.name.contains("ClassVault_") || cn.name.contains("$obfClassVault_")) continue;
            if (injectGuardCall(cn, guardName)) {
                instrumented++;
            }
        }

        log.info("Instrumented {} classes with anti-agent guard ({})", instrumented, guardName);
    }

    /* -------------------------- guard class -------------------------- */

    private static ClassNode buildGuardClass(String internalName) {
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V17;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = internalName;
        cn.superName = "java/lang/Object";
        cn.interfaces = new ArrayList<>();
        cn.fields = new ArrayList<>();
        cn.methods = new ArrayList<>();

        cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE | Opcodes.ACC_SYNTHETIC,
                FLAG_NAME, "Z", null, null));

        cn.methods.add(buildCheckMethod(internalName));

        // Default no-arg constructor (private — this class is never instantiated).
        MethodNode ctor = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC,
                "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxLocals = 1;
        ctor.maxStack = 1;
        cn.methods.add(ctor);

        return cn;
    }

    private static MethodNode buildCheckMethod(String owner) {
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                CHECK_NAME, "()V", null, null);
        InsnList il = mn.instructions;

        LabelNode begin = new LabelNode();
        LabelNode tryHandler = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode setFlagAndReturn = new LabelNode();

        il.add(begin);

        // if (checked) return;
        il.add(new FieldInsnNode(Opcodes.GETSTATIC, owner, FLAG_NAME, "Z"));
        LabelNode notCachedYet = new LabelNode();
        il.add(new JumpInsnNode(Opcodes.IFEQ, notCachedYet));
        il.add(new InsnNode(Opcodes.RETURN));
        il.add(notCachedYet);

        // try { List<String> args = ManagementFactory.getRuntimeMXBean().getInputArguments(); ... }
        LabelNode tryStart = new LabelNode();
        il.add(tryStart);

        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/management/ManagementFactory", "getRuntimeMXBean",
                "()Ljava/lang/management/RuntimeMXBean;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE,
                "java/lang/management/RuntimeMXBean", "getInputArguments",
                "()Ljava/util/List;", true));
        il.add(new VarInsnNode(Opcodes.ASTORE, 0));

        // Iterator<String> it = args.iterator();
        il.add(new VarInsnNode(Opcodes.ALOAD, 0));
        il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE,
                "java/util/List", "iterator", "()Ljava/util/Iterator;", true));
        il.add(new VarInsnNode(Opcodes.ASTORE, 1));

        LabelNode loopHead = new LabelNode();
        LabelNode loopExit = new LabelNode();
        il.add(loopHead);

        // while (it.hasNext())
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE,
                "java/util/Iterator", "hasNext", "()Z", true));
        il.add(new JumpInsnNode(Opcodes.IFEQ, loopExit));

        // String a = (String) it.next();
        il.add(new VarInsnNode(Opcodes.ALOAD, 1));
        il.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE,
                "java/util/Iterator", "next", "()Ljava/lang/Object;", true));
        il.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        il.add(new VarInsnNode(Opcodes.ASTORE, 2));

        // for each suspicious prefix: if (a.startsWith(prefix)) Runtime.getRuntime().halt(0);
        String[] prefixes = {
                "-agentlib:jdwp",
                "-Xrunjdwp",
                "-javaagent:",
                "-agentpath:",
        };
        for (String p : prefixes) {
            il.add(new VarInsnNode(Opcodes.ALOAD, 2));
            il.add(new LdcInsnNode(p));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                    "java/lang/String", "startsWith", "(Ljava/lang/String;)Z", false));
            LabelNode skip = new LabelNode();
            il.add(new JumpInsnNode(Opcodes.IFEQ, skip));
            il.add(haltCall());
            il.add(skip);
        }

        // also exact-match -Xdebug
        il.add(new VarInsnNode(Opcodes.ALOAD, 2));
        il.add(new LdcInsnNode("-Xdebug"));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false));
        LabelNode skipDebug = new LabelNode();
        il.add(new JumpInsnNode(Opcodes.IFEQ, skipDebug));
        il.add(haltCall());
        il.add(skipDebug);

        il.add(new JumpInsnNode(Opcodes.GOTO, loopHead));
        il.add(loopExit);
        il.add(tryEnd);

        // Fall through: cache the result and return.
        il.add(new JumpInsnNode(Opcodes.GOTO, setFlagAndReturn));

        // catch (Throwable) { /* swallow — degraded environments */ }
        il.add(tryHandler);
        il.add(new InsnNode(Opcodes.POP));

        il.add(setFlagAndReturn);
        il.add(new InsnNode(Opcodes.ICONST_1));
        il.add(new FieldInsnNode(Opcodes.PUTSTATIC, owner, FLAG_NAME, "Z"));
        il.add(new InsnNode(Opcodes.RETURN));

        mn.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(
                tryStart, tryEnd, tryHandler, "java/lang/Throwable"));

        mn.maxLocals = 3;
        mn.maxStack = 3;
        return mn;
    }

    private static InsnList haltCall() {
        InsnList il = new InsnList();
        il.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false));
        il.add(new InsnNode(Opcodes.ICONST_0));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Runtime", "halt", "(I)V", false));
        return il;
    }

    /* ------------------------ guard call inject ----------------------- */

    private static boolean injectGuardCall(ClassNode cn, String guardName) {
        MethodNode clinit = null;
        for (MethodNode mn : cn.methods) {
            if ("<clinit>".equals(mn.name)) {
                clinit = mn;
                break;
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(
                    Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            clinit.maxLocals = 0;
            clinit.maxStack = 1;
            cn.methods.add(clinit);
        }

        InsnList prologue = new InsnList();
        prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, guardName, CHECK_NAME, "()V", false));

        AbstractInsnNode first = clinit.instructions.getFirst();
        if (first == null) {
            clinit.instructions.add(prologue);
        } else {
            clinit.instructions.insertBefore(first, prologue);
        }
        if (clinit.maxStack < 1) clinit.maxStack = 1;
        return true;
    }
}
