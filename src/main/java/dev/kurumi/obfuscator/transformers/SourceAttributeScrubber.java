package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * Scrubs the {@code SourceFile} and {@code SourceDebug} attributes and
 * optionally replaces them with a plausible-looking fake so decompilers show
 * a misleading {@code // compiled from} banner.
 *
 * <p>Also wipes {@code InnerClasses} attributes for synthetic names that no
 * longer correspond to anything in the output.
 */
public class SourceAttributeScrubber implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(SourceAttributeScrubber.class);

    private static final String[] FAKE_NAMES = {
            "main.java", "Bootstrap.java", "Gen.java", "Module.java",
            "Runtime.java", "Entrypoint.java", "App.java", "_.java"
    };

    @Override
    public String name() {
        return "source-scrub";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        Random rnd = new Random(0xC0DEBABE);
        int scrubbed = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            cn.sourceFile = FAKE_NAMES[rnd.nextInt(FAKE_NAMES.length)];
            cn.sourceDebug = null;
            scrubbed++;
        }
        log.info("Scrubbed SourceFile/SourceDebug on {} classes", scrubbed);
    }
}
