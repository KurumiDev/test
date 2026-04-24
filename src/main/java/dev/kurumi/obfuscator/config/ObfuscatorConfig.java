package dev.kurumi.obfuscator.config;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Immutable, type-safe view over the HOCON configuration file. Values are
 * mirrored as fields so transformers don't need the Typesafe Config API.
 */
public class ObfuscatorConfig {

    public enum Target { AUTO, PAPER, BUNGEE, VELOCITY, FABRIC, FORGE, PLAIN }

    public enum NamingStrategy { ALPHABET, UNICODE, CONFUSE, RANDOM_HEX }

    public enum StringStrength { LIGHT, STANDARD, HEAVY }

    public enum FlowTechnique { BOGUS_JUMPS, EXCEPTION, GOTO_SPAGHETTI, ALL }

    public enum OpaqueType { MATH, RUNTIME, MIXED }

    private final Path input;
    private final Path output;
    private final List<Path> libraries;
    private final Target target;

    private final boolean renamerEnabled;
    private final NamingStrategy namingStrategy;
    private final boolean renameClasses;
    private final boolean renameMethods;
    private final boolean renameFields;
    private final boolean renameLocalVars;

    private final boolean stringEncryptionEnabled;
    private final StringStrength stringStrength;

    private final boolean flowEnabled;
    private final FlowTechnique flowTechnique;
    private final int flowComplexity;

    private final boolean bogusExceptionEnabled;

    private final boolean opaqueEnabled;
    private final OpaqueType opaqueType;

    private final boolean numberEnabled;
    private final boolean numberOnlyMagic;

    private final boolean invokeDynamicEnabled;
    private final boolean invokeDynamicAutoDetectLambdas;

    private final boolean classLiteralEnabled;
    private final boolean stringConcatEnabled;
    private final boolean indyCallEnabled;
    private final boolean indyFieldEnabled;
    private final boolean junkCodeEnabled;
    private final boolean accessFlagsEnabled;
    private final boolean memberShufflerEnabled;
    private final boolean sourceScrubEnabled;
    private final boolean blobStringEnabled;
    private final boolean localVarTableEnabled;
    private final boolean classExplodeEnabled;

    private final boolean localVarEnabled;

    private final List<String> exemptions;
    private final boolean autoExempt;

    private final boolean dryRun;
    private final Path saveMapping;
    private final boolean verifyAfterEach;
    private final boolean failOnVerifyError;

    public ObfuscatorConfig(Builder b) {
        this.input = b.input;
        this.output = b.output;
        this.libraries = List.copyOf(b.libraries);
        this.target = b.target;
        this.renamerEnabled = b.renamerEnabled;
        this.namingStrategy = b.namingStrategy;
        this.renameClasses = b.renameClasses;
        this.renameMethods = b.renameMethods;
        this.renameFields = b.renameFields;
        this.renameLocalVars = b.renameLocalVars;
        this.stringEncryptionEnabled = b.stringEncryptionEnabled;
        this.stringStrength = b.stringStrength;
        this.flowEnabled = b.flowEnabled;
        this.flowTechnique = b.flowTechnique;
        this.flowComplexity = b.flowComplexity;
        this.bogusExceptionEnabled = b.bogusExceptionEnabled;
        this.opaqueEnabled = b.opaqueEnabled;
        this.opaqueType = b.opaqueType;
        this.numberEnabled = b.numberEnabled;
        this.numberOnlyMagic = b.numberOnlyMagic;
        this.invokeDynamicEnabled = b.invokeDynamicEnabled;
        this.invokeDynamicAutoDetectLambdas = b.invokeDynamicAutoDetectLambdas;
        this.classLiteralEnabled = b.classLiteralEnabled;
        this.stringConcatEnabled = b.stringConcatEnabled;
        this.indyCallEnabled = b.indyCallEnabled;
        this.indyFieldEnabled = b.indyFieldEnabled;
        this.junkCodeEnabled = b.junkCodeEnabled;
        this.accessFlagsEnabled = b.accessFlagsEnabled;
        this.memberShufflerEnabled = b.memberShufflerEnabled;
        this.sourceScrubEnabled = b.sourceScrubEnabled;
        this.blobStringEnabled = b.blobStringEnabled;
        this.localVarTableEnabled = b.localVarTableEnabled;
        this.classExplodeEnabled = b.classExplodeEnabled;
        this.localVarEnabled = b.localVarEnabled;
        this.exemptions = List.copyOf(b.exemptions);
        this.autoExempt = b.autoExempt;
        this.dryRun = b.dryRun;
        this.saveMapping = b.saveMapping;
        this.verifyAfterEach = b.verifyAfterEach;
        this.failOnVerifyError = b.failOnVerifyError;
    }

    public static ObfuscatorConfig fromFile(Path file) {
        Config c = ConfigFactory.parseFile(file.toFile()).resolve();
        return fromConfig(c);
    }

    public static ObfuscatorConfig fromConfig(Config c) {
        Builder b = new Builder();
        if (c.hasPath("input")) b.input = Paths.get(c.getString("input"));
        if (c.hasPath("output")) b.output = Paths.get(c.getString("output"));
        if (c.hasPath("libraries")) {
            for (String lib : c.getStringList("libraries")) {
                b.libraries.add(Paths.get(lib));
            }
        }
        if (c.hasPath("target")) b.target = parseTarget(c.getString("target"));

        if (c.hasPath("transformers.renamer.enabled")) b.renamerEnabled = c.getBoolean("transformers.renamer.enabled");
        if (c.hasPath("transformers.renamer.strategy")) b.namingStrategy = NamingStrategy.valueOf(c.getString("transformers.renamer.strategy"));
        if (c.hasPath("transformers.renamer.rename-classes")) b.renameClasses = c.getBoolean("transformers.renamer.rename-classes");
        if (c.hasPath("transformers.renamer.rename-methods")) b.renameMethods = c.getBoolean("transformers.renamer.rename-methods");
        if (c.hasPath("transformers.renamer.rename-fields")) b.renameFields = c.getBoolean("transformers.renamer.rename-fields");
        if (c.hasPath("transformers.renamer.rename-local-vars")) b.renameLocalVars = c.getBoolean("transformers.renamer.rename-local-vars");

        if (c.hasPath("transformers.string-encryption.enabled")) b.stringEncryptionEnabled = c.getBoolean("transformers.string-encryption.enabled");
        if (c.hasPath("transformers.string-encryption.strength")) b.stringStrength = StringStrength.valueOf(c.getString("transformers.string-encryption.strength"));

        if (c.hasPath("transformers.flow-obfuscation.enabled")) b.flowEnabled = c.getBoolean("transformers.flow-obfuscation.enabled");
        if (c.hasPath("transformers.flow-obfuscation.technique")) b.flowTechnique = FlowTechnique.valueOf(c.getString("transformers.flow-obfuscation.technique"));
        if (c.hasPath("transformers.flow-obfuscation.complexity")) b.flowComplexity = c.getInt("transformers.flow-obfuscation.complexity");

        if (c.hasPath("transformers.bogus-exception.enabled")) b.bogusExceptionEnabled = c.getBoolean("transformers.bogus-exception.enabled");

        if (c.hasPath("transformers.opaque-predicates.enabled")) b.opaqueEnabled = c.getBoolean("transformers.opaque-predicates.enabled");
        if (c.hasPath("transformers.opaque-predicates.type")) b.opaqueType = OpaqueType.valueOf(c.getString("transformers.opaque-predicates.type"));

        if (c.hasPath("transformers.number-obfuscation.enabled")) b.numberEnabled = c.getBoolean("transformers.number-obfuscation.enabled");
        if (c.hasPath("transformers.number-obfuscation.only-magic-numbers")) b.numberOnlyMagic = c.getBoolean("transformers.number-obfuscation.only-magic-numbers");

        if (c.hasPath("transformers.invokedynamic.enabled")) b.invokeDynamicEnabled = c.getBoolean("transformers.invokedynamic.enabled");
        if (c.hasPath("transformers.invokedynamic.auto-detect-lambdas")) b.invokeDynamicAutoDetectLambdas = c.getBoolean("transformers.invokedynamic.auto-detect-lambdas");

        if (c.hasPath("transformers.class-literal.enabled")) b.classLiteralEnabled = c.getBoolean("transformers.class-literal.enabled");
        if (c.hasPath("transformers.string-concat.enabled")) b.stringConcatEnabled = c.getBoolean("transformers.string-concat.enabled");
        if (c.hasPath("transformers.indy-call.enabled")) b.indyCallEnabled = c.getBoolean("transformers.indy-call.enabled");
        if (c.hasPath("transformers.indy-field.enabled")) b.indyFieldEnabled = c.getBoolean("transformers.indy-field.enabled");
        if (c.hasPath("transformers.junk-code.enabled")) b.junkCodeEnabled = c.getBoolean("transformers.junk-code.enabled");
        if (c.hasPath("transformers.access-flags.enabled")) b.accessFlagsEnabled = c.getBoolean("transformers.access-flags.enabled");
        if (c.hasPath("transformers.member-shuffler.enabled")) b.memberShufflerEnabled = c.getBoolean("transformers.member-shuffler.enabled");
        if (c.hasPath("transformers.source-scrub.enabled")) b.sourceScrubEnabled = c.getBoolean("transformers.source-scrub.enabled");
        if (c.hasPath("transformers.blob-string.enabled")) b.blobStringEnabled = c.getBoolean("transformers.blob-string.enabled");
        if (c.hasPath("transformers.local-variable-table.enabled")) b.localVarTableEnabled = c.getBoolean("transformers.local-variable-table.enabled");
        if (c.hasPath("transformers.class-explode.enabled")) b.classExplodeEnabled = c.getBoolean("transformers.class-explode.enabled");

        if (c.hasPath("transformers.local-variable.enabled")) b.localVarEnabled = c.getBoolean("transformers.local-variable.enabled");

        if (c.hasPath("exemptions")) b.exemptions = new ArrayList<>(c.getStringList("exemptions"));

        if (c.hasPath("auto-exempt")) {
            // single boolean or per-target — just honour a single "enabled" if any per-target value is true
            Config ae = c.getConfig("auto-exempt");
            for (String key : List.of("paper", "fabric", "forge", "bungee", "velocity")) {
                if (ae.hasPath(key) && ae.getBoolean(key)) {
                    b.autoExempt = true;
                }
            }
        }

        if (c.hasPath("dry-run")) b.dryRun = c.getBoolean("dry-run");
        if (c.hasPath("save-mapping")) b.saveMapping = Paths.get(c.getString("save-mapping"));
        if (c.hasPath("verify-after-each")) b.verifyAfterEach = c.getBoolean("verify-after-each");
        if (c.hasPath("fail-on-verify-error")) b.failOnVerifyError = c.getBoolean("fail-on-verify-error");

        return new ObfuscatorConfig(b);
    }

    private static Target parseTarget(String s) {
        return Target.valueOf(s.toUpperCase());
    }

    public Path input() { return input; }
    public Path output() { return output; }
    public List<Path> libraries() { return libraries; }
    public Target target() { return target; }
    public NamingStrategy namingStrategy() { return namingStrategy; }
    public boolean renameClasses() { return renameClasses; }
    public boolean renameMethods() { return renameMethods; }
    public boolean renameFields() { return renameFields; }
    public boolean renameLocalVars() { return renameLocalVars; }
    public StringStrength stringStrength() { return stringStrength; }
    public FlowTechnique flowTechnique() { return flowTechnique; }
    public int flowComplexity() { return flowComplexity; }
    public OpaqueType opaqueType() { return opaqueType; }
    public boolean numberOnlyMagic() { return numberOnlyMagic; }
    public boolean invokeDynamicAutoDetectLambdas() { return invokeDynamicAutoDetectLambdas; }
    public List<String> exemptions() { return exemptions; }
    public boolean autoExempt() { return autoExempt; }
    public boolean dryRun() { return dryRun; }
    public Path saveMapping() { return saveMapping; }
    public boolean verifyAfterEach() { return verifyAfterEach; }
    public boolean failOnVerifyError() { return failOnVerifyError; }

    public boolean isTransformerEnabled(String name) {
        return switch (name) {
            case "renamer" -> renamerEnabled;
            case "string-encryption" -> stringEncryptionEnabled;
            case "flow-obfuscation" -> flowEnabled;
            case "bogus-exception" -> bogusExceptionEnabled;
            case "opaque-predicates" -> opaqueEnabled;
            case "number-obfuscation" -> numberEnabled;
            case "invokedynamic" -> invokeDynamicEnabled;
            case "class-literal" -> classLiteralEnabled;
            case "string-concat" -> stringConcatEnabled;
            case "indy-call" -> indyCallEnabled;
            case "indy-field" -> indyFieldEnabled;
            case "junk-code" -> junkCodeEnabled;
            case "access-flags" -> accessFlagsEnabled;
            case "member-shuffler" -> memberShufflerEnabled;
            case "source-scrub" -> sourceScrubEnabled;
            case "blob-string" -> blobStringEnabled;
            case "local-variable-table" -> localVarTableEnabled;
            case "local-variable" -> localVarEnabled;
            case "class-explode" -> classExplodeEnabled;
            default -> true;
        };
    }

    public static final class Builder {
        public Path input;
        public Path output;
        public List<Path> libraries = new ArrayList<>();
        public Target target = Target.AUTO;

        public boolean renamerEnabled = true;
        public NamingStrategy namingStrategy = NamingStrategy.ALPHABET;
        public boolean renameClasses = true;
        public boolean renameMethods = true;
        public boolean renameFields = true;
        public boolean renameLocalVars = true;

        public boolean stringEncryptionEnabled = true;
        public StringStrength stringStrength = StringStrength.STANDARD;

        public boolean flowEnabled = true;
        public FlowTechnique flowTechnique = FlowTechnique.BOGUS_JUMPS;
        public int flowComplexity = 2;

        public boolean bogusExceptionEnabled = false;

        public boolean opaqueEnabled = true;
        public OpaqueType opaqueType = OpaqueType.MATH;

        public boolean numberEnabled = true;
        public boolean numberOnlyMagic = true;

        public boolean invokeDynamicEnabled = false;
        public boolean invokeDynamicAutoDetectLambdas = true;

        public boolean classLiteralEnabled = true;
        public boolean stringConcatEnabled = true;
        public boolean indyCallEnabled = false; // opt-in: heavier but strongest
        public boolean indyFieldEnabled = false; // opt-in: indy-wraps field access
        public boolean junkCodeEnabled = true;
        public boolean accessFlagsEnabled = true;
        public boolean memberShufflerEnabled = true;
        public boolean sourceScrubEnabled = true;
        public boolean blobStringEnabled = false; // opt-in: replaces string-encryption
        public boolean localVarTableEnabled = true;
        public boolean classExplodeEnabled = false; // opt-in: inflates class count

        public boolean localVarEnabled = true;

        public List<String> exemptions = Collections.emptyList();
        public boolean autoExempt = true;

        public boolean dryRun = false;
        public Path saveMapping = null;
        public boolean verifyAfterEach = true;
        public boolean failOnVerifyError = false;

        public ObfuscatorConfig build() {
            return new ObfuscatorConfig(this);
        }
    }
}
