package dev.kurumi.obfuscator.verify;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.FrameComputingClassWriterFactory;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.util.ArrayList;
import java.util.List;

/**
 * Wraps ASM's {@link CheckClassAdapter} so transformers can request a
 * pool-wide verification pass between passes.
 */
public final class BytecodeVerifier {

    private BytecodeVerifier() {}

    public static List<String> verify(ClassPool pool, ClassNode cn) {
        FrameComputingClassWriterFactory factory = new FrameComputingClassWriterFactory(pool);
        byte[] bytes;
        try {
            bytes = factory.toBytes(cn);
        } catch (RuntimeException ex) {
            return List.of("serialization: " + ex.getMessage());
        }
        // Structural pass only. CheckClassAdapter's static data-flow
        // verification (verify()) instantiates SimpleVerifier, which tries to
        // resolve the bytecode's types through Class.forName - that fails
        // whenever the input references in-pool classes not present on our
        // runtime classpath. The structural pass still catches stack
        // inconsistencies, invalid labels, wrong opcodes, bad max values, etc.
        try {
            ClassReader cr = new ClassReader(bytes);
            CheckClassAdapter cca = new CheckClassAdapter(new ClassWriter(0), true);
            cr.accept(cca, 0);
        } catch (RuntimeException ex) {
            return List.of("verify: " + ex.getMessage());
        }
        return List.of();
    }

    public static List<String> verifyPool(ClassPool pool) {
        List<String> out = new ArrayList<>();
        for (ClassNode cn : pool.allClassNodes()) {
            List<String> errs = verify(pool, cn);
            if (!errs.isEmpty()) {
                out.add("in " + cn.name + ":");
                out.addAll(errs);
            }
        }
        return out;
    }
}
