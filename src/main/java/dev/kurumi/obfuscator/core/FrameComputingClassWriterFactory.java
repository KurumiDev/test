package dev.kurumi.obfuscator.core;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Produces {@link ClassWriter}s that compute frames using our in-memory class
 * pool instead of a classloader. Critical after flow obfuscation, where any
 * {@code getCommonSuperClass} call against a classloader would throw
 * {@link ClassNotFoundException} for classes that are present in the input
 * jar but not on the obfuscator's runtime classpath (e.g. shaded Gson, ASM,
 * Bukkit, ProtocolLib).
 *
 * <p>Falling back to {@code java/lang/Object} for unknown types is unsafe: at
 * a multi-catch handler ASM uses the common supertype as the type of the
 * caught reference on the verifier's operand stack. If the real common
 * supertype is e.g. {@code java/lang/RuntimeException} but we widen it to
 * {@code java/lang/Object}, any subsequent {@code invokevirtual} on that
 * reference (a frequent pattern in user code: {@code e.getMessage()}) fails
 * verification at JVM load time with
 * "Bad type on operand stack: Object is not assignable to RuntimeException".
 *
 * <p>Implementation: walk each type's superclass chain through the pool first
 * (covers shaded library classes whose definitions ARE in the input jar but
 * not in the classloader), and fall back to JDK reflection only for types
 * the pool doesn't know about (always JDK in practice).
 */
public class FrameComputingClassWriterFactory {

    private final ClassPool pool;

    public FrameComputingClassWriterFactory(ClassPool pool) {
        this.pool = pool;
    }

    public byte[] toBytes(ClassNode cn) {
        ClassWriter cw = new PoolAwareClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, pool);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private static final class PoolAwareClassWriter extends ClassWriter {
        private static final String OBJECT = "java/lang/Object";

        private final ClassPool pool;

        PoolAwareClassWriter(int flags, ClassPool pool) {
            super(flags);
            this.pool = pool;
        }

        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            if (type1.equals(type2)) return type1;
            if (OBJECT.equals(type1) || OBJECT.equals(type2)) return OBJECT;

            // Build type1's superclass chain, then walk type2 upward looking
            // for the first hit. This mirrors what ASM's default impl does
            // via Class.forName, but resolves classes through the in-memory
            // pool first so shaded library types (Gson, ASM, ProtocolLib …)
            // contribute their actual hierarchy instead of widening to Object.
            Set<String> chain1 = supertypeChain(type1);
            String cur = type2;
            int safety = 64;
            while (cur != null && safety-- > 0) {
                if (chain1.contains(cur)) return cur;
                cur = parentOf(cur);
            }
            return OBJECT;
        }

        private Set<String> supertypeChain(String internalName) {
            Set<String> chain = new LinkedHashSet<>();
            String cur = internalName;
            int safety = 64;
            while (cur != null && safety-- > 0) {
                if (!chain.add(cur)) break; // cycle guard
                cur = parentOf(cur);
            }
            chain.add(OBJECT);
            return chain;
        }

        /**
         * Returns the immediate superclass of {@code internalName}, consulting
         * the pool first and falling back to JDK reflection for types the pool
         * doesn't own. Returns {@code null} if neither source can resolve the
         * type — caller should treat that as "stop walking" and fall back to
         * {@link #OBJECT} (which is what the verifier accepts as a wildcard
         * upper bound).
         */
        private String parentOf(String internalName) {
            if (internalName == null || OBJECT.equals(internalName)) return null;

            ClassNode cn = pool.find(internalName);
            if (cn != null) {
                if ((cn.access & Opcodes.ACC_INTERFACE) != 0) {
                    // ASM's default impl returns Object for interface chains;
                    // we do the same so verifier-merge stays consistent.
                    return OBJECT;
                }
                return cn.superName;
            }

            // Pool miss → JDK lookup. This is the path JDK exception types
            // (IllegalStateException, IOException, …) take, since they're
            // not bundled into the user jar.
            try {
                Class<?> cls = Class.forName(internalName.replace('/', '.'), false,
                        Thread.currentThread().getContextClassLoader());
                if (cls.isInterface()) return OBJECT;
                Class<?> sup = cls.getSuperclass();
                return sup == null ? null : sup.getName().replace('.', '/');
            } catch (Throwable ignore) {
                return null;
            }
        }
    }
}
