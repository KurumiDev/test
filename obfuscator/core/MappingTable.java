package obfuscator.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores name mappings for retrace functionality.
 * Maps original names to obfuscated names and vice versa.
 */
public class MappingTable {
    private static final Logger LOG = LoggerFactory.getLogger(MappingTable.class);

    // className -> obfuscatedName
    private final Map<String, String> classMappings = new ConcurrentHashMap<>();
    // className -> (originalFieldName -> obfuscatedFieldName)
    private final Map<String, Map<String, String>> fieldMappings = new ConcurrentHashMap<>();
    // className -> (originalMethodDesc -> (originalMethodName -> obfuscatedMethodName))
    private final Map<String, Map<String, Map<String, String>>> methodMappings = new ConcurrentHashMap<>();

    public void addClassMapping(String original, String obfuscated) {
        classMappings.put(original, obfuscated);
    }

    public void addFieldMapping(String className, String original, String obfuscated) {
        fieldMappings.computeIfAbsent(className, k -> new HashMap<>()).put(original, obfuscated);
    }

    public void addMethodMapping(String className, String desc, String original, String obfuscated) {
        methodMappings
            .computeIfAbsent(className, k -> new HashMap<>())
            .computeIfAbsent(desc, k -> new HashMap<>())
            .put(original, obfuscated);
    }

    public String getObfuscatedClass(String original) {
        return classMappings.get(original);
    }

    public String getOriginalClass(String obfuscated) {
        for (Map.Entry<String, String> entry : classMappings.entrySet()) {
            if (entry.getValue().equals(obfuscated)) {
                return entry.getKey();
            }
        }
        return obfuscated;
    }

    public String getObfuscatedField(String className, String original) {
        Map<String, String> fields = fieldMappings.get(className);
        return fields != null ? fields.get(original) : original;
    }

    public String getObfuscatedMethod(String className, String desc, String original) {
        Map<String, Map<String, String>> classMethods = methodMappings.get(className);
        if (classMethods == null) return original;
        Map<String, String> methods = classMethods.get(desc);
        return methods != null ? methods.get(original) : original;
    }

    public Map<String, String> getClassMappings() {
        return classMappings;
    }

    public boolean hasClassMapping(String original) {
        return classMappings.containsKey(original);
    }

    public void save(Path path) throws IOException {
        LOG.info("Saving mapping table to {}", path);
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(Files.newOutputStream(path)))) {
            // Classes
            for (Map.Entry<String, String> entry : new TreeMap<>(classMappings).entrySet()) {
                pw.println(entry.getKey() + " -> " + entry.getValue());
            }
            pw.println();

            // Fields
            for (Map.Entry<String, Map<String, String>> classEntry : new TreeMap<>(fieldMappings).entrySet()) {
                String className = classEntry.getKey();
                for (Map.Entry<String, String> fieldEntry : classEntry.getValue().entrySet()) {
                    pw.println(className + "." + fieldEntry.getKey() + " -> " + fieldEntry.getValue());
                }
            }
            pw.println();

            // Methods
            for (Map.Entry<String, Map<String, Map<String, String>>> classEntry : new TreeMap<>(methodMappings).entrySet()) {
                String className = classEntry.getKey();
                for (Map.Entry<String, Map<String, String>> descEntry : classEntry.getValue().entrySet()) {
                    String desc = descEntry.getKey();
                    for (Map.Entry<String, String> methodEntry : descEntry.getValue().entrySet()) {
                        pw.println(className + "." + methodEntry.getKey() + desc + " -> " + methodEntry.getValue());
                    }
                }
            }
        }
        LOG.info("Mapping table saved with {} classes, {} fields, {} methods",
                classMappings.size(),
                fieldMappings.values().stream().mapToInt(Map::size).sum(),
                methodMappings.values().stream()
                    .flatMap(m -> m.values().stream())
                    .mapToInt(Map::size)
                    .sum());
    }

    public static MappingTable load(Path path) throws IOException {
        MappingTable table = new MappingTable();
        LOG.info("Loading mapping table from {}", path);
        
        for (String line : Files.readAllLines(path)) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            
            String[] parts = line.split(" -> ");
            if (parts.length != 2) continue;
            
            String original = parts[0].trim();
            String obfuscated = parts[1].trim();
            
            if (original.contains(".")) {
                // Field or method
                int dotIdx = original.lastIndexOf('.');
                String className = original.substring(0, dotIdx);
                String member = original.substring(dotIdx + 1);
                
                if (member.contains("(")) {
                    // Method
                    int parenIdx = member.indexOf('(');
                    String methodName = member.substring(0, parenIdx);
                    String desc = member.substring(parenIdx);
                    table.addMethodMapping(className, desc, methodName, obfuscated);
                } else {
                    // Field
                    table.addFieldMapping(className, member, obfuscated);
                }
            } else {
                // Class
                table.addClassMapping(original, obfuscated);
            }
        }
        
        return table;
    }

    public void clear() {
        classMappings.clear();
        fieldMappings.clear();
        methodMappings.clear();
    }

    public int getClassCount() { return classMappings.size(); }
    public int getFieldCount() { return fieldMappings.values().stream().mapToInt(Map::size).sum(); }
    public int getMethodCount() { 
        return methodMappings.values().stream()
            .flatMap(m -> m.values().stream())
            .mapToInt(Map::size)
            .sum();
    }
}
