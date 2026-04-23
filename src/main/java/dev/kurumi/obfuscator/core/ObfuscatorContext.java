package dev.kurumi.obfuscator.core;

import dev.kurumi.obfuscator.analysis.AnnotationScanner;
import dev.kurumi.obfuscator.analysis.InheritanceAnalyzer;
import dev.kurumi.obfuscator.config.ExemptionResolver;
import dev.kurumi.obfuscator.config.ObfuscatorConfig;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shared state passed between transformers: configuration, exemption rules,
 * analysis results, and the final rename mapping (which retrace later consumes).
 */
public class ObfuscatorContext {

    private final ObfuscatorConfig config;
    private final ExemptionResolver exemptions;
    private InheritanceAnalyzer inheritance;
    private AnnotationScanner annotations;

    /** Class-level mapping: internal old name -> internal new name. */
    private final Map<String, String> classMapping = new LinkedHashMap<>();
    /** Method mapping: owner+name+desc -> new name. */
    private final Map<String, String> methodMapping = new LinkedHashMap<>();
    /** Field mapping: owner+name+desc -> new name. */
    private final Map<String, String> fieldMapping = new LinkedHashMap<>();

    public ObfuscatorContext(ObfuscatorConfig config, ExemptionResolver exemptions) {
        this.config = config;
        this.exemptions = exemptions;
    }

    public ObfuscatorConfig config() {
        return config;
    }

    public ExemptionResolver exemptions() {
        return exemptions;
    }

    public InheritanceAnalyzer inheritance() {
        return inheritance;
    }

    public void setInheritance(InheritanceAnalyzer inheritance) {
        this.inheritance = inheritance;
    }

    public AnnotationScanner annotations() {
        return annotations;
    }

    public void setAnnotations(AnnotationScanner annotations) {
        this.annotations = annotations;
    }

    public Map<String, String> classMapping() {
        return classMapping;
    }

    public Map<String, String> methodMapping() {
        return methodMapping;
    }

    public Map<String, String> fieldMapping() {
        return fieldMapping;
    }

    public static String methodKey(String owner, String name, String desc) {
        return owner + '.' + name + desc;
    }

    public static String fieldKey(String owner, String name, String desc) {
        return owner + '.' + name + ':' + desc;
    }
}
