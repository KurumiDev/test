package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LocalVariableTransformer — переименовывает локальные переменные
 */
public class LocalVariableTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(LocalVariableTransformer.class);

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public LocalVariableTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        if (!config.isRenameLocalVars()) {
            logger.info("Local variable renaming disabled");
            return;
        }

        logger.info("Starting local variable renaming...");

        int renamed = 0;
        var nameGen = new com.obfuscator.util.NameGenerator(config.getRenamingStrategy());

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            for (MethodNode method : cn.methods) {
                if (method.instructions == null) continue;

                // Переименовываем локальные переменные
                if (method.localVariables != null) {
                    for (var lv : method.localVariables) {
                        if (lv.name != null && !lv.name.startsWith("this")) {
                            lv.name = nameGen.generateLocalVarName();
                            renamed++;
                        }
                    }
                }

                // Также можно добавить debug info removal
                if (method.visibleLocalVariableAnnotations != null) {
                    method.visibleLocalVariableAnnotations.clear();
                }
                if (method.invisibleLocalVariableAnnotations != null) {
                    method.invisibleLocalVariableAnnotations.clear();
                }
            }
        }

        logger.info("Local variable renaming completed. Renamed {} variables", renamed);
    }

    @Override
    public String getName() {
        return "LocalVariableTransformer";
    }
}
