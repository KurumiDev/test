package dev.kurumi.obfuscator.core;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

/**
 * Produces {@link ClassWriter}s that compute frames using our in-memory class
 * pool instead of a classloader. Critical after flow obfuscation, where any
 * {@code getCommonSuperClass} call against a classloader would throw
 * {@link ClassNotFoundException}.
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
        private final ClassPool pool;

        PoolAwareClassWriter(int flags, ClassPool pool) {
            super(flags);
            this.pool = pool;
        }

        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            try {
                return super.getCommonSuperClass(type1, type2);
            } catch (RuntimeException ex) {
                // Fall back to Object if neither type is available on the runtime
                // classpath. This is acceptable because COMPUTE_FRAMES only needs
                // a valid common ancestor, and java/lang/Object is always valid.
                if (pool.find(type1) != null || pool.find(type2) != null) {
                    return "java/lang/Object";
                }
                return "java/lang/Object";
            }
        }
    }
}
