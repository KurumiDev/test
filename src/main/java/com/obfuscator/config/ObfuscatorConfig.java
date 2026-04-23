package com.obfuscator.config;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Конфигурация обфускатора
 */
public class ObfuscatorConfig {
    private final Config config;

    // Target type
    private TargetType targetType = TargetType.AUTO;

    // Input/Output
    private Path inputPath;
    private Path outputPath;
    private List<Path> libraries = Collections.emptyList();

    // Renamer settings
    private boolean renamerEnabled = true;
    private RenamingStrategy renamingStrategy = RenamingStrategy.UNICODE;
    private boolean renameClasses = true;
    private boolean renameMethods = true;
    private boolean renameFields = true;
    private boolean renameLocalVars = true;

    // String encryption
    private boolean stringEncryptionEnabled = true;
    private EncryptionStrength encryptionStrength = EncryptionStrength.HEAVY;

    // Flow obfuscation
    private boolean flowObfuscationEnabled = true;
    private FlowTechnique flowTechnique = FlowTechnique.ALL;
    private int flowComplexity = 2;

    // Opaque predicates
    private boolean opaquePredicatesEnabled = true;
    private OpaquePredicateType opaquePredicateType = OpaquePredicateType.MIXED;

    // Number obfuscation
    private boolean numberObfuscationEnabled = true;
    private boolean onlyMagicNumbers = true;

    // InvokeDynamic
    private boolean invokeDynamicEnabled = false;
    private boolean autoDetectLambdas = true;

    // Exemptions
    private List<String> exemptions = Collections.emptyList();
    private boolean autoExemptPaper = true;
    private boolean autoExemptFabric = false;
    private boolean autoExemptForge = false;
    private boolean autoExemptBungee = false;
    private boolean autoExemptVelocity = false;

    // Mapping file
    private Path mappingPath;
    private boolean saveMapping = true;

    public enum TargetType {
        AUTO, PAPER, FABRIC, FORGE, BUNGEE, VELOCITY, PLAIN
    }

    public enum RenamingStrategy {
        ALPHABET, UNICODE, CONFUSE, RANDOM_HEX
    }

    public enum EncryptionStrength {
        LIGHT, STANDARD, HEAVY
    }

    public enum FlowTechnique {
        BOGUS_JUMPS, EXCEPTION, GOTO_SPAGHETTI, ALL
    }

    public enum OpaquePredicateType {
        MATH, RUNTIME, MIXED
    }

    public ObfuscatorConfig() {
        this.config = ConfigFactory.empty();
    }

    public ObfuscatorConfig(Path configPath) {
        this.config = ConfigFactory.parseFile(configPath.toFile()).resolve();
    }

    public static ObfuscatorConfig load(Path path) {
        return new ObfuscatorConfig(path);
    }

    public static ObfuscatorConfig createDefault() {
        return new ObfuscatorConfig();
    }

    // Getters
    public TargetType getTargetType() {
        return targetType;
    }

    public Path getInputPath() {
        return inputPath;
    }

    public Path getOutputPath() {
        return outputPath;
    }

    public List<Path> getLibraries() {
        return libraries;
    }

    public boolean isRenamerEnabled() {
        return renamerEnabled;
    }

    public RenamingStrategy getRenamingStrategy() {
        return renamingStrategy;
    }

    public boolean isRenameClasses() {
        return renameClasses;
    }

    public boolean isRenameMethods() {
        return renameMethods;
    }

    public boolean isRenameFields() {
        return renameFields;
    }

    public boolean isRenameLocalVars() {
        return renameLocalVars;
    }

    public boolean isStringEncryptionEnabled() {
        return stringEncryptionEnabled;
    }

    public EncryptionStrength getEncryptionStrength() {
        return encryptionStrength;
    }

    public boolean isFlowObfuscationEnabled() {
        return flowObfuscationEnabled;
    }

    public FlowTechnique getFlowTechnique() {
        return flowTechnique;
    }

    public int getFlowComplexity() {
        return flowComplexity;
    }

    public boolean isOpaquePredicatesEnabled() {
        return opaquePredicatesEnabled;
    }

    public OpaquePredicateType getOpaquePredicateType() {
        return opaquePredicateType;
    }

    public boolean isNumberObfuscationEnabled() {
        return numberObfuscationEnabled;
    }

    public boolean isOnlyMagicNumbers() {
        return onlyMagicNumbers;
    }

    public boolean isInvokeDynamicEnabled() {
        return invokeDynamicEnabled;
    }

    public boolean isAutoDetectLambdas() {
        return autoDetectLambdas;
    }

    public List<String> getExemptions() {
        return exemptions;
    }

    public Set<String> getExemptAnnotations() {
        if (autoExemptPaper) {
            return com.obfuscator.compat.PaperPluginCompat.getExemptAnnotations();
        }
        return Collections.emptySet();
    }

    public boolean shouldSaveMapping() {
        return saveMapping;
    }

    public Path getMappingPath() {
        return mappingPath;
    }

    // Fluent setters
    public ObfuscatorConfig setTargetType(TargetType targetType) {
        this.targetType = targetType;
        return this;
    }

    public ObfuscatorConfig setInputPath(Path inputPath) {
        this.inputPath = inputPath;
        return this;
    }

    public ObfuscatorConfig setOutputPath(Path outputPath) {
        this.outputPath = outputPath;
        return this;
    }

    public ObfuscatorConfig setLibraries(List<Path> libraries) {
        this.libraries = libraries;
        return this;
    }

    public ObfuscatorConfig setRenamerEnabled(boolean enabled) {
        this.renamerEnabled = enabled;
        return this;
    }

    public ObfuscatorConfig setRenamingStrategy(RenamingStrategy strategy) {
        this.renamingStrategy = strategy;
        return this;
    }

    public ObfuscatorConfig setRenameClasses(boolean rename) {
        this.renameClasses = rename;
        return this;
    }

    public ObfuscatorConfig setRenameMethods(boolean rename) {
        this.renameMethods = rename;
        return this;
    }

    public ObfuscatorConfig setRenameFields(boolean rename) {
        this.renameFields = rename;
        return this;
    }

    public ObfuscatorConfig setRenameLocalVars(boolean rename) {
        this.renameLocalVars = rename;
        return this;
    }

    public ObfuscatorConfig setStringEncryptionEnabled(boolean enabled) {
        this.stringEncryptionEnabled = enabled;
        return this;
    }

    public ObfuscatorConfig setEncryptionStrength(EncryptionStrength strength) {
        this.encryptionStrength = strength;
        return this;
    }

    public ObfuscatorConfig setFlowObfuscationEnabled(boolean enabled) {
        this.flowObfuscationEnabled = enabled;
        return this;
    }

    public ObfuscatorConfig setFlowTechnique(FlowTechnique technique) {
        this.flowTechnique = technique;
        return this;
    }

    public ObfuscatorConfig setFlowComplexity(int complexity) {
        this.flowComplexity = complexity;
        return this;
    }

    public ObfuscatorConfig setOpaquePredicatesEnabled(boolean enabled) {
        this.opaquePredicatesEnabled = enabled;
        return this;
    }

    public ObfuscatorConfig setOpaquePredicateType(OpaquePredicateType type) {
        this.opaquePredicateType = type;
        return this;
    }

    public ObfuscatorConfig setNumberObfuscationEnabled(boolean enabled) {
        this.numberObfuscationEnabled = enabled;
        return this;
    }

    public ObfuscatorConfig setOnlyMagicNumbers(boolean only) {
        this.onlyMagicNumbers = only;
        return this;
    }

    public ObfuscatorConfig setInvokeDynamicEnabled(boolean enabled) {
        this.invokeDynamicEnabled = enabled;
        return this;
    }

    public ObfuscatorConfig setAutoDetectLambdas(boolean detect) {
        this.autoDetectLambdas = detect;
        return this;
    }

    public ObfuscatorConfig setExemptions(List<String> exemptions) {
        this.exemptions = exemptions;
        return this;
    }

    public ObfuscatorConfig setAutoExemptPaper(boolean exempt) {
        this.autoExemptPaper = exempt;
        return this;
    }

    public ObfuscatorConfig setMappingPath(Path path) {
        this.mappingPath = path;
        return this;
    }

    public ObfuscatorConfig setSaveMapping(boolean save) {
        this.saveMapping = save;
        return this;
    }

    public void applyFromConfigFile() {
        if (config.isEmpty()) {
            return;
        }

        if (config.hasPath("target")) {
            this.targetType = TargetType.valueOf(config.getString("target").toUpperCase());
        }

        if (config.hasPath("transformers.renamer.enabled")) {
            this.renamerEnabled = config.getBoolean("transformers.renamer.enabled");
        }

        if (config.hasPath("transformers.renamer.strategy")) {
            this.renamingStrategy = RenamingStrategy.valueOf(config.getString("transformers.renamer.strategy").toUpperCase());
        }

        if (config.hasPath("transformers.string-encryption.enabled")) {
            this.stringEncryptionEnabled = config.getBoolean("transformers.string-encryption.enabled");
        }

        if (config.hasPath("transformers.string-encryption.strength")) {
            this.encryptionStrength = EncryptionStrength.valueOf(config.getString("transformers.string-encryption.strength").toUpperCase());
        }

        if (config.hasPath("transformers.flow-obfuscation.enabled")) {
            this.flowObfuscationEnabled = config.getBoolean("transformers.flow-obfuscation.enabled");
        }

        if (config.hasPath("transformers.opaque-predicates.enabled")) {
            this.opaquePredicatesEnabled = config.getBoolean("transformers.opaque-predicates.enabled");
        }

        if (config.hasPath("transformers.number-obfuscation.enabled")) {
            this.numberObfuscationEnabled = config.getBoolean("transformers.number-obfuscation.enabled");
        }

        if (config.hasPath("transformers.invokedynamic.enabled")) {
            this.invokeDynamicEnabled = config.getBoolean("transformers.invokedynamic.enabled");
        }

        if (config.hasPath("exemptions")) {
            this.exemptions = config.getStringList("exemptions");
        }
    }
}
