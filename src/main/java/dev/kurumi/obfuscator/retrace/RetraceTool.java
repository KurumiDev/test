package dev.kurumi.obfuscator.retrace;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reverses the mapping file emitted by the obfuscator to turn an obfuscated
 * stack trace back into something readable.
 */
public class RetraceTool {

    private final Map<String, String> invertedClass = new LinkedHashMap<>();
    /** Obfuscated "owner.name" -> original method name (descriptor agnostic). */
    private final Map<String, String> invertedMember = new LinkedHashMap<>();
    private final Map<String, String> classForwards = new LinkedHashMap<>();

    public RetraceTool(Path mappingFile) throws IOException {
        parse(Files.readString(mappingFile));
    }

    public RetraceTool(String mappingContent) {
        parse(mappingContent);
    }

    private void parse(String content) {
        String currentOriginalOwner = null;
        String currentObfuscatedOwner = null;
        for (String rawLine : content.split("\n")) {
            if (rawLine.isBlank()) continue;
            if (rawLine.startsWith("    ")) {
                String trimmed = rawLine.trim();
                if (currentObfuscatedOwner == null) continue;
                int arrow = trimmed.indexOf(" -> ");
                if (arrow < 0) continue;
                String origLeft = trimmed.substring(0, arrow);
                String newRight = trimmed.substring(arrow + 4);
                boolean isField = origLeft.startsWith("#");
                if (isField) origLeft = origLeft.substring(1);
                // methods look like "foo(I)V"; fields look like "bar:I"
                String origSimple;
                if (isField) {
                    origSimple = origLeft.substring(0, origLeft.indexOf(':'));
                } else {
                    int paren = origLeft.indexOf('(');
                    origSimple = paren < 0 ? origLeft : origLeft.substring(0, paren);
                }
                invertedMember.put(currentObfuscatedOwner.replace('/', '.') + "." + newRight, origSimple);
            } else {
                int arrow = rawLine.indexOf(" -> ");
                if (arrow < 0) continue;
                String orig = rawLine.substring(0, arrow);
                String obf = rawLine.substring(arrow + 4);
                currentOriginalOwner = orig;
                currentObfuscatedOwner = obf;
                classForwards.put(orig, obf);
                invertedClass.put(obf.replace('/', '.'), orig.replace('/', '.'));
            }
        }
    }

    public String retrace(String trace) {
        String[] lines = trace.split("\n");
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            out.append(retraceLine(line)).append('\n');
        }
        return out.toString();
    }

    private String retraceLine(String line) {
        // "	at pkg.Cls.method(Cls.java:12)"
        int atIdx = line.indexOf("at ");
        if (atIdx < 0) return line;
        int parenStart = line.indexOf('(', atIdx);
        if (parenStart < 0) return line;
        String head = line.substring(0, atIdx + 3);
        String methodRef = line.substring(atIdx + 3, parenStart);
        String tail = line.substring(parenStart);
        int lastDot = methodRef.lastIndexOf('.');
        if (lastDot < 0) return line;
        String cls = methodRef.substring(0, lastDot);
        String method = methodRef.substring(lastDot + 1);
        String originalCls = invertedClass.getOrDefault(cls, cls);
        String originalMethod = invertedMember.getOrDefault(cls + "." + method, method);
        return head + originalCls + "." + originalMethod + tail;
    }

    public Map<String, String> classMapping() {
        return classForwards;
    }

    public Map<String, String> invertedClassMap() {
        return invertedClass;
    }
}
