package obfuscator.transformers.phase1;

import obfuscator.core.ClassPool;
import obfuscator.core.MappingTable;
import obfuscator.analysis.ExemptionResolver;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Renames classes, methods, fields using various naming strategies.
 */
public class RenamerTransformer {
    private static final Logger LOG = LoggerFactory.getLogger(RenamerTransformer.class);

    public enum NamingStrategy {
        ALPHABET,      // a, b, c, ... aa, ab
        UNICODE,       // \u0000\u0001 - breaks most IDEs/decompilers
        CONFUSE,       // Il1IlIl1lIl - visually indistinguishable
        SLASH_TRICK,   // packages like a/b/../c (legal in bytecode, breaks decompilers)
        KEYWORD_ABUSE  // names matching Java keywords: "if", "for", "class"
    }

    private final ClassPool pool;
    private final MappingTable mappingTable;
    private final ExemptionResolver exemptions;
    private final NamingStrategy strategy;
    private final boolean renameClasses;
    private final boolean renameMethods;
    private final boolean renameFields;
    private final boolean renamePackages;

    // Name generators
    private int alphabetCounter = 0;
    private int unicodeCounter = 0;
    private final Random random = new Random(42); // Fixed seed for reproducibility

    // Reserved Java keywords for KEYWORD_ABUSE
    private static final List<String> KEYWORDS = Arrays.asList(
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "break", "continue", "return", "try", "catch", "finally", "throw", "throws",
        "new", "class", "interface", "enum", "extends", "implements", "import",
        "package", "public", "private", "protected", "static", "final", "abstract",
        "native", "synchronized", "volatile", "transient", "strictfp", "assert",
        "instanceof", "super", "this", "void", "boolean", "byte", "char", "short",
        "int", "long", "float", "double", "true", "false", "null"
    );

    public RenamerTransformer(ClassPool pool, MappingTable mappingTable, 
                              ExemptionResolver exemptions, NamingStrategy strategy,
                              boolean renameClasses, boolean renameMethods, 
                              boolean renameFields, boolean renamePackages) {
        this.pool = pool;
        this.mappingTable = mappingTable;
        this.exemptions = exemptions;
        this.strategy = strategy;
        this.renameClasses = renameClasses;
        this.renameMethods = renameMethods;
        this.renameFields = renameFields;
        this.renamePackages = renamePackages;
    }

    public void transform() {
        LOG.info("Starting renaming with strategy: {}", strategy);

        // Build all mappings first
        Map<String, String> classMappings = buildClassMappings();
        Map<String, Map<String, String>> methodMappings = buildMethodMappings(classMappings);
        Map<String, Map<String, String>> fieldMappings = buildFieldMappings(classMappings);

        // Apply remapping to all classes
        RemapperImpl remapper = new RemapperImpl(classMappings, methodMappings, fieldMappings);
        
        for (ClassNode cn : pool.getOwnClasses()) {
            cn.accept(remapper);
        }

        LOG.info("Renaming complete: {} classes, {} methods, {} fields renamed",
                classMappings.size(),
                methodMappings.values().stream().mapToInt(Map::size).sum(),
                fieldMappings.values().stream().mapToInt(Map::size).sum());
    }

    private Map<String, String> buildClassMappings() {
        Map<String, String> mappings = new HashMap<>();
        
        if (!renameClasses) return mappings;

        for (ClassNode cn : pool.getOwnClasses()) {
            if (exemptions.isClassExempt(cn.name)) {
                LOG.debug("Skipping exempt class: {}", cn.name);
                continue;
            }

            // Don't rename record classes (Java 16+)
            if ((cn.access & org.objectweb.asm.OACC_RECORD) != 0) {
                LOG.debug("Skipping record class: {}", cn.name);
                continue;
            }

            String newName = generateClassName();
            mappings.put(cn.name, newName);
            mappingTable.addClassMapping(cn.name, newName);
        }

        return mappings;
    }

    private Map<String, Map<String, String>> buildMethodMappings(Map<String, String> classMappings) {
        Map<String, Map<String, String>> mappings = new HashMap<>();

        if (!renameMethods) return mappings;

        for (ClassNode cn : pool.getOwnClasses()) {
            String mappedClassName = classMappings.getOrDefault(cn.name, cn.name);
            Map<String, String> classMethodMappings = new HashMap<>();

            for (var mn : cn.methods) {
                // Skip special methods
                if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) {
                    continue;
                }

                // Skip bridge/synthetic methods
                if ((mn.access & org.objectweb.asm.OACC_BRIDGE) != 0) {
                    continue;
                }

                if (exemptions.isMethodExempt(cn.name, mn.name, mn.desc)) {
                    continue;
                }

                String newName = generateMethodName();
                classMethodMappings.put(mn.name + mn.desc, newName);
                mappingTable.addMethodMapping(mappedClassName, mn.desc, mn.name, newName);
            }

            if (!classMethodMappings.isEmpty()) {
                mappings.put(cn.name, classMethodMappings);
            }
        }

        return mappings;
    }

    private Map<String, Map<String, String>> buildFieldMappings(Map<String, String> classMappings) {
        Map<String, Map<String, String>> mappings = new HashMap<>();

        if (!renameFields) return mappings;

        for (ClassNode cn : pool.getOwnClasses()) {
            String mappedClassName = classMappings.getOrDefault(cn.name, cn.name);
            Map<String, String> classFieldMappings = new HashMap<>();

            if (cn.fields == null) continue;

            for (var fn : cn.fields) {
                // Skip enum constants
                if ((fn.access & org.objectweb.asm.OACC_ENUM) != 0) {
                    continue;
                }

                // Skip final static fields (constants)
                if ((fn.access & org.objectweb.asm.OACC_FINAL) != 0 &&
                    (fn.access & org.objectweb.asm.OACC_STATIC) != 0) {
                    continue;
                }

                if (exemptions.isFieldExempt(cn.name, fn.name)) {
                    continue;
                }

                String newName = generateFieldName();
                classFieldMappings.put(fn.name, newName);
                mappingTable.addFieldMapping(mappedClassName, fn.name, newName);
            }

            if (!classFieldMappings.isEmpty()) {
                mappings.put(cn.name, classFieldMappings);
            }
        }

        return mappings;
    }

    private String generateClassName() {
        return switch (strategy) {
            case ALPHABET -> generateAlphabetName();
            case UNICODE -> generateUnicodeName();
            case CONFUSE -> generateConfuseName();
            case SLASH_TRICK -> generateSlashTrickName();
            case KEYWORD_ABUSE -> generateKeywordName();
        };
    }

    private String generateMethodName() {
        return switch (strategy) {
            case ALPHABET -> "m" + generateAlphabetName();
            case UNICODE -> "\u0000\u0000" + (unicodeCounter++);
            case CONFUSE -> generateConfuseName();
            case SLASH_TRICK -> "m" + generateAlphabetName();
            case KEYWORD_ABUSE -> KEYWORDS.get(random.nextInt(KEYWORDS.size()));
        };
    }

    private String generateFieldName() {
        return switch (strategy) {
            case ALPHABET -> generateAlphabetName();
            case UNICODE -> "\u0000" + (unicodeCounter++);
            case CONFUSE -> generateConfuseName();
            case SLASH_TRICK -> generateAlphabetName();
            case KEYWORD_ABUSE -> KEYWORDS.get(random.nextInt(KEYWORDS.size()));
        };
    }

    private String generateAlphabetName() {
        StringBuilder sb = new StringBuilder();
        int n = alphabetCounter++;
        do {
            sb.append((char)('a' + (n % 26)));
            n /= 26;
        } while (n > 0);
        return sb.toString();
    }

    private String generateUnicodeName() {
        char c1 = (char)(unicodeCounter & 0xFF);
        char c2 = (char)((unicodeCounter >> 8) & 0xFF);
        unicodeCounter++;
        return "" + c1 + c2;
    }

    private String generateConfuseName() {
        String[] chars = {"I", "l", "1"};
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append(chars[random.nextInt(chars.length)]);
        }
        return sb.toString();
    }

    private String generateSlashTrickName() {
        // Creates package-like names that confuse decompilers
        int depth = random.nextInt(3) + 1;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            if (i > 0) sb.append('/');
            sb.append(generateAlphabetName());
            if (random.nextBoolean()) {
                sb.append("/..");
            }
        }
        sb.append('/').append(generateAlphabetName());
        return sb.toString();
    }

    private String generateKeywordName() {
        return KEYWORDS.get(random.nextInt(KEYWORDS.size()));
    }

    /**
     * ASM Remapper implementation for applying name changes
     */
    private static class RemapperImpl extends Remapper {
        private final Map<String, String> classMappings;
        private final Map<String, Map<String, String>> methodMappings;
        private final Map<String, Map<String, String>> fieldMappings;

        public RemapperImpl(Map<String, String> classMappings,
                           Map<String, Map<String, String>> methodMappings,
                           Map<String, Map<String, String>> fieldMappings) {
            this.classMappings = classMappings;
            this.methodMappings = methodMappings;
            this.fieldMappings = fieldMappings;
        }

        @Override
        public String map(String internalName) {
            return classMappings.getOrDefault(internalName, internalName);
        }

        @Override
        public String mapMethodName(String owner, String name, String desc) {
            Map<String, String> methods = methodMappings.get(owner);
            if (methods != null) {
                return methods.getOrDefault(name + desc, name);
            }
            return name;
        }

        @Override
        public String mapFieldName(String owner, String name, String desc) {
            Map<String, String> fields = fieldMappings.get(owner);
            if (fields != null) {
                return fields.getOrDefault(name, name);
            }
            return name;
        }

        @Override
        public String mapDesc(String desc) {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < desc.length(); i++) {
                char c = desc.charAt(i);
                if (c == 'L') {
                    int end = desc.indexOf(';', i);
                    String typeName = desc.substring(i + 1, end);
                    String mapped = map(typeName);
                    result.append('L').append(mapped).append(';');
                    i = end;
                } else if (c == '[') {
                    result.append(c);
                } else {
                    result.append(c);
                }
            }
            return result.toString();
        }

        @Override
        public String mapType(String type) {
            if (type.endsWith(";")) {
                // Object type
                if (type.startsWith("[")) {
                    // Array of objects
                    StringBuilder result = new StringBuilder();
                    for (char c : type.toCharArray()) {
                        if (c == '[') result.append(c);
                        else if (c == 'L') result.append('L').append(map(type.substring(type.indexOf('L') + 1, type.length() - 1))).append(';');
                    }
                    return result.toString();
                } else {
                    return 'L' + map(type.substring(1, type.length() - 1)) + ';';
                }
            }
            return type;
        }
    }
}
