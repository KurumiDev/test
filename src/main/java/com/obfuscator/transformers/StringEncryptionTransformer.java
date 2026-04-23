package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * StringEncryptionTransformer — шифрует строковые константы
 * 
 * Уровни:
 * - LIGHT    → простой XOR с фиксированным ключом
 * - STANDARD → XOR с ключом производным от имени класса
 * - HEAVY    → per-class + per-method + runtime stack key
 */
public class StringEncryptionTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(StringEncryptionTransformer.class);

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public StringEncryptionTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        logger.info("Starting string encryption (strength: {})...", config.getEncryptionStrength());

        int encrypted = 0;

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            // Шифрование строк будет реализовано здесь
            // Пока просто пропускаем
        }

        logger.info("String encryption completed. Encrypted {} strings", encrypted);
    }

    @Override
    public String getName() {
        return "StringEncryptionTransformer";
    }
}
