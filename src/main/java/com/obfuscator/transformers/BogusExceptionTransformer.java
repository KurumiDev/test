package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BogusExceptionTransformer — добавляет bogus exception-based flow
 */
public class BogusExceptionTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(BogusExceptionTransformer.class);

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public BogusExceptionTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        logger.info("Starting bogus exception transformation...");
        // Реализация будет добавлена
        logger.info("Bogus exception transformation completed");
    }

    @Override
    public String getName() {
        return "BogusExceptionTransformer";
    }
}
