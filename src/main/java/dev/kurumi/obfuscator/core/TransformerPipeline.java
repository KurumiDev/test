package dev.kurumi.obfuscator.core;

import dev.kurumi.obfuscator.analysis.AnnotationScanner;
import dev.kurumi.obfuscator.analysis.DependencyAnalyzer;
import dev.kurumi.obfuscator.analysis.InheritanceAnalyzer;
import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.transformers.AccessFlagObfuscator;
import dev.kurumi.obfuscator.transformers.BlobStringTransformer;
import dev.kurumi.obfuscator.transformers.BogusExceptionTransformer;
import dev.kurumi.obfuscator.transformers.ClassLiteralTransformer;
import dev.kurumi.obfuscator.transformers.FlowObfuscationTransformer;
import dev.kurumi.obfuscator.transformers.IndyCallTransformer;
import dev.kurumi.obfuscator.transformers.InvokeDynamicTransformer;
import dev.kurumi.obfuscator.transformers.JunkCodeInjector;
import dev.kurumi.obfuscator.transformers.LocalVariableTableObfuscator;
import dev.kurumi.obfuscator.transformers.LocalVariableTransformer;
import dev.kurumi.obfuscator.transformers.MemberShufflerTransformer;
import dev.kurumi.obfuscator.transformers.NumberObfuscationTransformer;
import dev.kurumi.obfuscator.transformers.OpaquePredicateTransformer;
import dev.kurumi.obfuscator.transformers.RenamerTransformer;
import dev.kurumi.obfuscator.transformers.SourceAttributeScrubber;
import dev.kurumi.obfuscator.transformers.StringConcatTransformer;
import dev.kurumi.obfuscator.transformers.StringEncryptionTransformer;
import dev.kurumi.obfuscator.verify.BytecodeVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Fixed-order pipeline of analysis + transformation passes. Ordering is
 * deliberate: analysis first, then name-changing passes, then bytecode
 * mutations that add/remove instructions, and cosmetic passes last.
 */
public class TransformerPipeline {

    private static final Logger log = LoggerFactory.getLogger(TransformerPipeline.class);

    private final ObfuscatorConfig config;
    private final List<Transformer> transformers = new ArrayList<>();

    public TransformerPipeline(ObfuscatorConfig config) {
        this.config = config;

        // 1. Analysis (always on, not gated by config)
        transformers.add(new DependencyAnalyzer());
        transformers.add(new InheritanceAnalyzer());
        transformers.add(new AnnotationScanner());

        // 2. Renamer: changes every reference everywhere
        transformers.add(new RenamerTransformer());

        // 3. Number obfuscation BEFORE flow, so jump targets stay stable
        transformers.add(new NumberObfuscationTransformer());

        // 4. Class literal rewriting — emits LDC strings consumed by the next pass
        transformers.add(new ClassLiteralTransformer());

        // 5. makeConcatWithConstants → StringBuilder chain (also produces LDC strings)
        transformers.add(new StringConcatTransformer());

        // 6a. Optional: blob-string packs all LDCs into a per-class encrypted
        //     byte[] BEFORE string-encryption. When enabled it consumes every
        //     LDC string so StringEncryption has nothing to wrap.
        transformers.add(new BlobStringTransformer());

        // 6b. String encryption (sees every remaining LDC string)
        transformers.add(new StringEncryptionTransformer());

        // 5. Bogus exception wrapping (lightweight flow distortion)
        transformers.add(new BogusExceptionTransformer());

        // 6. Flow obfuscation: heavy bytecode mutation
        transformers.add(new FlowObfuscationTransformer());

        // 7. Opaque predicates
        transformers.add(new OpaquePredicateTransformer());

        // 8. InvokeDynamic (last major pass, with lambda-guard)
        transformers.add(new InvokeDynamicTransformer());

        // 9. Indy-call wrapping for cross-pool method calls
        transformers.add(new IndyCallTransformer());

        // 10. Decoy methods
        transformers.add(new JunkCodeInjector());

        // 11. Cosmetic: access flags, member order, source attributes
        transformers.add(new AccessFlagObfuscator());
        transformers.add(new MemberShufflerTransformer());
        transformers.add(new SourceAttributeScrubber());

        // 12. Local var table cleanup (strip debug LocalVariableTable)
        transformers.add(new LocalVariableTransformer());

        // 13. Synthetic LocalVariableTable with confusing names (after strip)
        transformers.add(new LocalVariableTableObfuscator());
    }

    public void execute(ClassPool pool, ObfuscatorContext ctx) {
        for (Transformer t : transformers) {
            boolean analysisPass = t instanceof DependencyAnalyzer
                    || t instanceof InheritanceAnalyzer
                    || t instanceof AnnotationScanner;
            if (!analysisPass && !t.isEnabled(config)) {
                log.debug("Skipping disabled transformer: {}", t.name());
                continue;
            }
            log.info("Running: {}", t.name());
            long start = System.nanoTime();
            t.transform(pool, ctx);
            long elapsed = (System.nanoTime() - start) / 1_000_000L;
            log.info("  -> done in {}ms", elapsed);

            if (!analysisPass && config.verifyAfterEach()) {
                List<String> errs = BytecodeVerifier.verifyPool(pool);
                if (!errs.isEmpty()) {
                    log.error("Verification errors after {}:", t.name());
                    for (String e : errs) log.error("  {}", e);
                    if (config.failOnVerifyError()) {
                        throw new IllegalStateException("Bytecode verification failed after " + t.name());
                    }
                }
            }
        }
    }
}
