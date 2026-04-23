package dev.kurumi.obfuscator.config;

import java.util.List;

/**
 * Thin facade around the exemption rule grammar. Kept separate from
 * {@link ExemptionResolver} so that CLI tooling (e.g. {@code --show-rules}) can
 * inspect the parsed rules without pulling in runtime pool state.
 */
public final class RuleEngine {

    private RuleEngine() {}

    public static boolean isValidRule(String raw) {
        if (raw == null || raw.isBlank()) return false;
        if (raw.startsWith("@")) return raw.length() > 1;
        if (raw.contains("#")) {
            String[] parts = raw.split("#", 2);
            return !parts[0].isBlank() && !parts[1].isBlank();
        }
        return true;
    }

    public static List<String> describe(List<String> rules) {
        return rules.stream().map(RuleEngine::describeOne).toList();
    }

    private static String describeOne(String raw) {
        if (raw.startsWith("@")) return "annotation: " + raw.substring(1);
        if (raw.contains("#")) return "method: " + raw;
        if (raw.endsWith(".**")) return "package (recursive): " + raw;
        return "class: " + raw;
    }
}
