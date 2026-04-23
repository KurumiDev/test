package dev.kurumi.obfuscator.analysis;

import dev.kurumi.obfuscator.compat.TargetDetector;
import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * First analysis pass. Detects the platform (Paper / Fabric / etc.) when the
 * config sets {@code target = auto}, and activates the matching compat
 * providers on the {@link dev.kurumi.obfuscator.config.ExemptionResolver}.
 */
public class DependencyAnalyzer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(DependencyAnalyzer.class);

    @Override
    public String name() {
        return "dependency-analyzer";
    }

    @Override
    public boolean isEnabled(ObfuscatorConfig cfg) {
        return true;
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        ObfuscatorConfig.Target target = ctx.config().target();
        if (target == ObfuscatorConfig.Target.AUTO) {
            target = TargetDetector.detect(pool);
            log.info("Auto-detected target: {}", target);
        } else {
            log.info("Using configured target: {}", target);
        }
        ctx.exemptions().activate(target, pool);
    }
}
