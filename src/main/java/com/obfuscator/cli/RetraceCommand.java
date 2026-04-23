package com.obfuscator.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RetraceCommand - утилита для восстановления имён из обфусцированных stack traces
 */
public class RetraceCommand {

    private final Map<String, String> classMapping = new HashMap<>();
    private final Map<String, Map<String, String>> methodMapping = new HashMap<>();
    private final Map<String, Map<String, String>> fieldMapping = new HashMap<>();

    public Integer run(File mappingFile, File traceFile, File outputFile) throws Exception {
        if (!mappingFile.exists()) {
            System.err.println("[ERROR] Mapping file not found: " + mappingFile.getAbsolutePath());
            return 1;
        }

        loadMapping(mappingFile.toPath());
        System.out.println("[+] Loaded mapping: " + classMapping.size() + " classes");

        String trace;
        if (traceFile != null) {
            trace = Files.readString(traceFile.toPath());
        } else {
            trace = readStdin();
        }

        String retraced = retrace(trace);

        if (outputFile != null) {
            Files.writeString(outputFile.toPath(), retraced);
            System.out.println("[+] Retraced trace written to: " + outputFile.getAbsolutePath());
        } else {
            System.out.println("\n=== RETRACED STACK TRACE ===");
            System.out.println(retraced);
        }

        return 0;
    }

    private void loadMapping(Path mappingPath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(mappingPath.toFile()))) {
            String line;
            String currentClass = null;

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                // Class mapping: com/example/MyClass → a/b/C
                if (line.contains("→")) {
                    String[] parts = line.split("→");
                    if (parts.length == 2) {
                        String original = parts[0].trim();
                        String obfuscated = parts[1].trim();

                        if (original.contains("/")) {
                            // This is a class mapping
                            classMapping.put(obfuscated, original);
                            currentClass = original;
                            methodMapping.put(original, new HashMap<>());
                            fieldMapping.put(original, new HashMap<>());
                        } else if (currentClass != null) {
                            // This is a member mapping
                            Matcher methodMatcher = Pattern.compile(
                                "(.*?)\\s+(\\w+)\\((.*)?\\)\\s*→\\s*(.*?)\\s+(\\w+)\\((.*)?\\)"
                            ).matcher(line);

                            if (methodMatcher.matches()) {
                                String obfMethod = methodMatcher.group(5);
                                String origMethod = methodMatcher.group(2);
                                String signature = methodMatcher.group(1) + "(" + 
                                    (methodMatcher.group(3) != null ? methodMatcher.group(3) : "") + ")";
                                methodMapping.get(currentClass).put(
                                    obfMethod + signature.replace(" ", ""),
                                    origMethod + signature.replace(" ", "")
                                );
                            } else {
                                // Field mapping
                                Matcher fieldMatcher = Pattern.compile(
                                    "(\\S+)\\s+(\\w+)\\s*→\\s*(\\S+)\\s+(\\w+)"
                                ).matcher(line);
                                if (fieldMatcher.matches()) {
                                    String obfField = fieldMatcher.group(4);
                                    String origField = fieldMatcher.group(2);
                                    fieldMapping.get(currentClass).put(obfField, origField);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private String retrace(String trace) {
        String result = trace;

        // Replace class names
        for (Map.Entry<String, String> entry : classMapping.entrySet()) {
            String obf = entry.getKey().replace("/", ".");
            String orig = entry.getValue().replace("/", ".");
            
            result = result.replaceAll("\\b" + Pattern.quote(obf) + "\\b", orig);
            
            String obfInternal = obf.replace(".", "/");
            String origInternal = orig.replace(".", "/");
            result = result.replaceAll(Pattern.quote(obfInternal), origInternal);
        }

        // Replace method names
        for (Map.Entry<String, Map<String, String>> classEntry : methodMapping.entrySet()) {
            for (Map.Entry<String, String> methodEntry : classEntry.getValue().entrySet()) {
                String obfMethod = methodEntry.getKey();
                String origMethod = methodEntry.getValue();
                
                String obfName = obfMethod.split("\\(")[0];
                String origName = origMethod.split("\\(")[0];
                
                if (!obfName.equals(origName)) {
                    result = result.replaceAll("\\b" + Pattern.quote(obfName) + "\\b(?=\\()", origName);
                }
            }
        }

        return result;
    }

    private String readStdin() throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new java.io.InputStreamReader(System.in));
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        return sb.toString();
    }
}
