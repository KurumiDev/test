package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * Injects decoy methods that look like real business logic but are never
 * actually invoked. The bodies reference common library classes (collections,
 * crypto, IO) so a reverse engineer wastes time reading them before noticing
 * there are no call sites.
 *
 * <p>Decoys are marked {@code ACC_SYNTHETIC | ACC_PRIVATE} so JVM tooling
 * recognizes them as compiler-generated and skips them when running proguard
 * mappings or similar audits. The JVM itself verifies them like any other
 * method, so they must be well-formed bytecode (they are).
 */
public class JunkCodeInjector implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(JunkCodeInjector.class);

    @Override
    public String name() {
        return "junk-code";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        Random rnd = new Random(0xDEADC0DEL);
        int injected = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            if ((cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0) continue;
            int n = 1 + rnd.nextInt(2);
            for (int i = 0; i < n; i++) {
                String name = "$obfJk" + Integer.toHexString(rnd.nextInt());
                cn.methods.add(buildDecoy(name, rnd));
                injected++;
            }
        }
        log.info("Injected {} junk methods across {} classes", injected, pool.allClassNodes().size());
    }

    private MethodNode buildDecoy(String name, Random rnd) {
        MethodNode mn = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                name,
                "(J)J",
                null,
                null
        );
        InsnList il = mn.instructions;
        // StringBuilder to look like business-logic
        il.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        il.add(new InsnNode(Opcodes.DUP));
        il.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder",
                "<init>", "()V", false));
        int stores = 2 + rnd.nextInt(3);
        for (int i = 0; i < stores; i++) {
            il.add(new LdcInsnNode(fakeString(rnd)));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                    "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
            il.add(new VarInsnNode(Opcodes.LLOAD, 0));
            il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                    "append", "(J)Ljava/lang/StringBuilder;", false));
        }
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder",
                "toString", "()Ljava/lang/String;", false));
        il.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String",
                "hashCode", "()I", false));
        il.add(new InsnNode(Opcodes.I2L));
        // Mix with input
        il.add(new VarInsnNode(Opcodes.LLOAD, 0));
        il.add(new InsnNode(Opcodes.LXOR));
        il.add(new LdcInsnNode(rnd.nextLong()));
        il.add(new InsnNode(Opcodes.LADD));
        il.add(new InsnNode(Opcodes.LRETURN));
        mn.maxLocals = 2;
        mn.maxStack = 6;
        return mn;
    }

    private static final String[] FAKE_STRINGS = {
            "session-", "nonce=", "rev:", "hash/", "mac:",
            "etag-", "k=", "iv:", "q-", "tenant/"
    };

    private static String fakeString(Random rnd) {
        return FAKE_STRINGS[rnd.nextInt(FAKE_STRINGS.length)];
    }
}
