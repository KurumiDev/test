package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Strips debug-oriented metadata (line numbers, source file, local variable
 * names) after all name-preserving transforms have run.
 */
public class LocalVariableTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(LocalVariableTransformer.class);

    @Override
    public String name() {
        return "local-variable";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int stripped = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            cn.sourceFile = null;
            cn.sourceDebug = null;
            for (MethodNode mn : cn.methods) {
                mn.localVariables = null;
                mn.parameters = null;
                if (mn.visibleLocalVariableAnnotations != null) mn.visibleLocalVariableAnnotations.clear();
                if (mn.invisibleLocalVariableAnnotations != null) mn.invisibleLocalVariableAnnotations.clear();
                stripped++;
            }
        }
        log.info("Stripped debug metadata from {} methods", stripped);
    }
}
