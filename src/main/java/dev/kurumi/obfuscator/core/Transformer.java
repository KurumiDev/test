package dev.kurumi.obfuscator.core;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;

/**
 * Base contract implemented by every analysis or transformation pass in the
 * pipeline.
 */
public interface Transformer {

    /** Stable, human-friendly name used in logs and config lookups. */
    String name();

    /** Execute this transformer against the supplied class pool. */
    void transform(ClassPool pool, ObfuscatorContext ctx);

    /** Whether this transformer is enabled by the config. Defaults to {@code true}. */
    default boolean isEnabled(ObfuscatorConfig cfg) {
        return cfg.isTransformerEnabled(name());
    }
}
