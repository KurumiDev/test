package dev.kurumi.obfuscator.config;

import dev.kurumi.obfuscator.compat.BungeeCompat;
import dev.kurumi.obfuscator.compat.CompatProvider;
import dev.kurumi.obfuscator.compat.FabricCompat;
import dev.kurumi.obfuscator.compat.ForgeCompat;
import dev.kurumi.obfuscator.compat.PaperPluginCompat;
import dev.kurumi.obfuscator.compat.VelocityCompat;
import dev.kurumi.obfuscator.core.ClassPool;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Decides which classes/methods/fields must not be renamed. Combines explicit
 * user rules from the config with automatic exemptions from the various
 * platform compat providers.
 */
public class ExemptionResolver {

    private final ObfuscatorConfig config;
    private final List<Rule> rules = new ArrayList<>();
    private final Set<String> exemptAnnotations = new HashSet<>();
    private final Set<String> exemptMethodSignatures = new HashSet<>();
    private final Set<String> exemptClassNames = new HashSet<>();
    private final List<CompatProvider> activeProviders = new ArrayList<>();

    public ExemptionResolver(ObfuscatorConfig config) {
        this.config = config;
        for (String raw : config.exemptions()) {
            rules.add(Rule.parse(raw));
        }
    }

    /** Activate the appropriate compat providers based on detected target. */
    public void activate(ObfuscatorConfig.Target target, ClassPool pool) {
        if (!config.autoExempt()) return;
        switch (target) {
            case PAPER -> activeProviders.add(new PaperPluginCompat());
            case BUNGEE -> activeProviders.add(new BungeeCompat());
            case VELOCITY -> activeProviders.add(new VelocityCompat());
            case FABRIC -> activeProviders.add(new FabricCompat());
            case FORGE -> activeProviders.add(new ForgeCompat());
            case AUTO -> {
                // When AUTO failed to detect anything specific, layer Paper by default
                // because it has the broadest overlap with typical JAR shapes.
                activeProviders.add(new PaperPluginCompat());
            }
            case PLAIN -> { /* no compat */ }
            default -> { /* explicit: already handled above */ }
        }
        for (CompatProvider cp : activeProviders) {
            exemptAnnotations.addAll(cp.exemptAnnotations());
            exemptMethodSignatures.addAll(cp.exemptMethodSignatures());
            exemptClassNames.addAll(cp.exemptClassSuperTypes());
        }
    }

    public Set<String> exemptAnnotations() {
        return exemptAnnotations;
    }

    public Set<String> exemptMethodSignatures() {
        return exemptMethodSignatures;
    }

    public Set<String> exemptClassSuperTypes() {
        return exemptClassNames;
    }

    /** True when this class should not be renamed at all. */
    public boolean isClassExempt(String internalName) {
        String dotted = internalName.replace('/', '.');
        for (Rule rule : rules) {
            if (rule.kind == RuleKind.CLASS && rule.matchesClass(dotted)) return true;
            if (rule.kind == RuleKind.PACKAGE && rule.matchesPackage(dotted)) return true;
        }
        return false;
    }

    /** True when this method should not be renamed. */
    public boolean isMethodExempt(String classInternal, String methodName, String desc) {
        String dotted = classInternal.replace('/', '.');
        for (Rule rule : rules) {
            if (rule.kind == RuleKind.CLASS_METHOD
                    && rule.matchesClass(dotted)
                    && rule.member.equals(methodName)) {
                return true;
            }
        }
        String sig = methodName + desc;
        if (exemptMethodSignatures.contains(sig)) return true;
        // partial match: prompt sometimes lists truncated sigs like "onCommand(Lorg/bukkit/...;...)"
        for (String ex : exemptMethodSignatures) {
            if (ex.startsWith(methodName + "(") && ex.contains("...")) {
                return true;
            }
        }
        return false;
    }

    public boolean isAnnotationExempt(String annotationDesc) {
        if (exemptAnnotations.contains(annotationDesc)) return true;
        // substring match for prefix-style entries like "Lorg/bukkit/plugin/java/annotation/;"
        for (String ex : exemptAnnotations) {
            if (ex.endsWith("/;") && annotationDesc.startsWith(ex.substring(0, ex.length() - 1))) {
                return true;
            }
        }
        return false;
    }

    private enum RuleKind { CLASS, PACKAGE, CLASS_METHOD, ANNOTATION }

    private static final class Rule {
        final RuleKind kind;
        final String classPattern;
        final String member;

        Rule(RuleKind kind, String classPattern, String member) {
            this.kind = kind;
            this.classPattern = classPattern;
            this.member = member;
        }

        static Rule parse(String raw) {
            if (raw.startsWith("@")) {
                return new Rule(RuleKind.ANNOTATION, raw.substring(1), null);
            }
            if (raw.contains("#")) {
                String[] split = raw.split("#", 2);
                return new Rule(RuleKind.CLASS_METHOD, split[0], split[1]);
            }
            if (raw.endsWith(".**")) {
                return new Rule(RuleKind.PACKAGE, raw.substring(0, raw.length() - 3), null);
            }
            return new Rule(RuleKind.CLASS, raw, null);
        }

        boolean matchesClass(String dotted) {
            return classPattern.equals(dotted);
        }

        boolean matchesPackage(String dotted) {
            return dotted.startsWith(classPattern + ".");
        }
    }
}
