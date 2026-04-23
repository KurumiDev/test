package obfuscator.analysis;

import obfuscator.core.ClassPool;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * Resolves all exemptions from various sources:
 * - Annotations
 * - Inheritance graph
 * - Config file
 * - Compatibility profiles
 */
public class ExemptionResolver {
    private static final Logger LOG = LoggerFactory.getLogger(ExemptionResolver.class);

    private final AnnotationScanner annotationScanner;
    private final InheritanceGraph inheritanceGraph;

    // Final resolved exemptions
    private final Set<String> exemptClasses;
    private final Set<String> exemptMethods;  // className.methodName+desc
    private final Set<String> exemptFields;   // className.fieldName

    public ExemptionResolver(AnnotationScanner annotationScanner, InheritanceGraph inheritanceGraph) {
        this.annotationScanner = annotationScanner;
        this.inheritanceGraph = inheritanceGraph;
        this.exemptClasses = new java.util.HashSet<>();
        this.exemptMethods = new java.util.HashSet<>();
        this.exemptFields = new java.util.HashSet<>();
    }

    public void resolve(ClassPool pool) {
        LOG.info("Resolving exemptions...");

        // From annotations
        exemptClasses.addAll(annotationScanner.getProtectedClasses());
        exemptMethods.addAll(annotationScanner.getProtectedMethods());
        exemptFields.addAll(annotationScanner.getProtectedFields());

        // From inheritance analysis
        for (ClassNode cn : pool.getOwnClasses()) {
            // Check if class can be renamed based on inheritance
            if (!inheritanceGraph.canRenameClass(cn.name)) {
                exemptClasses.add(cn.name);
            }

            // Check methods
            for (var mn : cn.methods) {
                if (!inheritanceGraph.canRenameMethod(cn.name, mn.name, mn.desc)) {
                    exemptMethods.add(cn.name + "." + mn.name + mn.desc);
                }
            }

            // Check fields
            for (var fn : cn.fields) {
                if (!inheritanceGraph.canRenameField(cn.name, fn.name)) {
                    exemptFields.add(cn.name + "." + fn.name);
                }
            }
        }

        LOG.info("Resolved exemptions: {} classes, {} methods, {} fields",
                exemptClasses.size(), exemptMethods.size(), exemptFields.size());
    }

    public boolean isClassExempt(String className) {
        return exemptClasses.contains(className);
    }

    public boolean isMethodExempt(String className, String methodName, String methodDesc) {
        return exemptMethods.contains(className + "." + methodName + methodDesc);
    }

    public boolean isFieldExempt(String className, String fieldName) {
        return exemptFields.contains(className + "." + fieldName);
    }

    public void addExemptClass(String className) {
        exemptClasses.add(className);
    }

    public void addExemptMethod(String className, String methodName, String methodDesc) {
        exemptMethods.add(className + "." + methodName + methodDesc);
    }

    public void addExemptField(String className, String fieldName) {
        exemptFields.add(className + "." + fieldName);
    }

    public void addExemptPattern(String pattern) {
        // Pattern matching for exemptions (e.g., "com/example/api/**")
        // This would be called from config parsing
        LOG.debug("Adding exemption pattern: {}", pattern);
        // Implementation would match against class/method/field names
    }

    public Set<String> getExemptClasses() {
        return java.util.Collections.unmodifiableSet(exemptClasses);
    }

    public Set<String> getExemptMethods() {
        return java.util.Collections.unmodifiableSet(exemptMethods);
    }

    public Set<String> getExemptFields() {
        return java.util.Collections.unmodifiableSet(exemptFields);
    }
}
