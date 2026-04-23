package com.obfuscator.core;

import com.obfuscator.analysis.AnalysisPhase;
import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.transformers.Transformer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * TransformerPipeline — цепочка трансформеров
 * ПОРЯДОК КРИТИЧЕН:
 * 1. Analysis — сначала анализируем, потом трансформируем
 * 2. Renamer — переименовываем (меняет все ссылки)
 * 3. Numbers — числовая обфускация (до flow, чтобы не ломать jump targets)
 * 4. Strings — шифрование строк
 * 5. Flow — поток управления (последним — самый деструктивный)
 * 6. InvokeDyn — invokedynamic (после flow)
 */
public class TransformerPipeline {
    private static final Logger logger = LoggerFactory.getLogger(TransformerPipeline.class);

    private final List<Object> phases = new ArrayList<>();
    private final ClassPool classPool;

    public TransformerPipeline(ClassPool classPool) {
        this.classPool = classPool;
    }

    /**
     * Добавить фазу анализа в pipeline
     */
    public TransformerPipeline addAnalysis(AnalysisPhase phase) {
        phases.add(phase);
        return this;
    }

    /**
     * Добавить трансформер в pipeline
     */
    public TransformerPipeline add(Transformer transformer) {
        phases.add(transformer);
        return this;
    }

    /**
     * Выполнить все фазы по порядку
     */
    public void execute() {
        logger.info("Starting transformer pipeline with {} phases", phases.size());

        for (Object phase : phases) {
            long startTime = System.currentTimeMillis();
            
            if (phase instanceof AnalysisPhase analysis) {
                logger.debug("Executing analysis phase: {}", analysis.getName());
                analysis.analyze();
            } else if (phase instanceof Transformer transformer) {
                logger.debug("Executing transformer: {}", transformer.getName());
                transformer.transform(classPool);
            }
            
            long endTime = System.currentTimeMillis();
            logger.info("Completed {} in {}ms", 
                phase instanceof AnalysisPhase ? ((AnalysisPhase) phase).getName() :
                                                 ((Transformer) phase).getName(),
                (endTime - startTime));
        }

        logger.info("Transformer pipeline completed");
    }

    /**
     * Стандартный порядок трансформеров для Paper плагинов
     */
    public static TransformerPipeline createDefault(ClassPool classPool, ObfuscatorConfig config) {
        TransformerPipeline pipeline = new TransformerPipeline(classPool);

        // Phase 1: Analysis
        pipeline.addAnalysis(new com.obfuscator.analysis.DependencyAnalyzer(classPool));
        pipeline.addAnalysis(new com.obfuscator.analysis.InheritanceAnalyzer(classPool));
        pipeline.addAnalysis(new com.obfuscator.analysis.AnnotationScanner(classPool));

        // Phase 2: Transformations
        if (config.isRenamerEnabled()) {
            pipeline.add(new com.obfuscator.transformers.RenamerTransformer(classPool, config));
        }

        if (config.isNumberObfuscationEnabled()) {
            pipeline.add(new com.obfuscator.transformers.NumberObfuscationTransformer(classPool, config));
        }

        if (config.isStringEncryptionEnabled()) {
            pipeline.add(new com.obfuscator.transformers.StringEncryptionTransformer(classPool, config));
        }

        if (config.isFlowObfuscationEnabled()) {
            pipeline.add(new com.obfuscator.transformers.BogusExceptionTransformer(classPool, config));
            pipeline.add(new com.obfuscator.transformers.FlowObfuscationTransformer(classPool, config));
        }

        if (config.isOpaquePredicatesEnabled()) {
            pipeline.add(new com.obfuscator.transformers.OpaquePredicateTransformer(classPool, config));
        }

        if (config.isInvokeDynamicEnabled()) {
            pipeline.add(new com.obfuscator.transformers.InvokeDynamicTransformer(classPool, config));
        }

        // Always apply local variable renaming
        pipeline.add(new com.obfuscator.transformers.LocalVariableTransformer(classPool, config));

        return pipeline;
    }
}
