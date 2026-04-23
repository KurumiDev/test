package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * NumberObfuscationTransformer — обфусцирует числовые константы
 * Заменяет числа на вычисления которые дают тот же результат
 */
public class NumberObfuscationTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(NumberObfuscationTransformer.class);

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public NumberObfuscationTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        logger.info("Starting number obfuscation...");

        int transformed = 0;

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            for (var method : cn.methods) {
                if (method.instructions == null) continue;

                for (AbstractInsnNode insn : method.instructions) {
                    // Обфускация чисел будет реализована здесь
                    // Пока просто пропускаем
                }
            }
        }

        logger.info("Number obfuscation completed. Transformed {} constants", transformed);
    }

    @Override
    public String getName() {
        return "NumberObfuscationTransformer";
    }
}
