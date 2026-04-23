package obfuscator.analysis;

import obfuscator.core.ClassPool;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.FieldNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Scans classes for annotations that should be exempt from obfuscation.
 */
public class AnnotationScanner {
    private static final Logger LOG = LoggerFactory.getLogger(AnnotationScanner.class);

    // Annotations that protect methods from renaming
    private static final Set<String> METHOD_PROTECTING_ANNOTATIONS = new HashSet<>(Arrays.asList(
        "org/bukkit/event/EventHandler",
        "net/md_5/bungee/event/EventHandler",
        "com/velocitypowered/api/event/Subscribe",
        "net/minecraftforge/eventbus/api/SubscribeEvent",
        "net/fabricmc/fabric/api/event/Event",
        "org/jetbrains/annotations/NotNull",
        "org/jetbrains/annotations/Nullable",
        "com/google/gson/annotations/SerializedName",
        "com/google/gson/annotations/Expose",
        "com/fasterxml/jackson/annotation/JsonProperty",
        "com/fasterxml/jackson/annotation/JsonIgnore",
        "javax/annotation/PostConstruct",
        "javax/annotation/PreDestroy",
        "java/lang/Override",
        "java/lang/Deprecated",
        "kotlin/jvm/JvmStatic",
        "kotlin/jvm/JvmName",
        "org/spongepowered/api/event/Listener",
        "org/spongepowered/api/util/annotation/EventOrder"
    ));

    // Annotations that protect classes from renaming
    private static final Set<String> CLASS_PROTECTING_ANNOTATIONS = new HashSet<>(Arrays.asList(
        "net/fabricmc/api/ModInitializer",
        "net/minecraftforge/fml/common/Mod",
        "org/bukkit/plugin/java/JavaPlugin",
        "net/md_5/bungee/api/plugin/Plugin",
        "com/velocitypowered/api/plugin/Plugin",
        "org/spongepowered/api/plugin/Plugin"
    ));

    // Annotated members that should not be obfuscated
    private final Set<String> protectedMethods = new HashSet<>();  // className.methodName+desc
    private final Set<String> protectedFields = new HashSet<>();   // className.fieldName
    private final Set<String> protectedClasses = new HashSet<>();  // className

    public void scan(ClassPool pool) {
        LOG.info("Scanning for protected annotations...");

        for (ClassNode cn : pool.getOwnClasses()) {
            scanClass(cn);
        }

        LOG.info("Found {} protected classes, {} protected methods, {} protected fields",
                protectedClasses.size(), protectedMethods.size(), protectedFields.size());
    }

    private void scanClass(ClassNode cn) {
        // Check class-level annotations
        if (cn.visibleAnnotations != null) {
            for (AnnotationNode an : cn.visibleAnnotations) {
                String desc = an.desc.replace("L", "").replace(";", "");
                if (CLASS_PROTECTING_ANNOTATIONS.contains(desc)) {
                    protectedClasses.add(cn.name);
                    LOG.debug("Class {} protected by @{}", cn.name, desc);
                }
            }
        }

        // Check method annotations
        for (MethodNode mn : cn.methods) {
            if (mn.visibleAnnotations != null) {
                for (AnnotationNode an : mn.visibleAnnotations) {
                    String desc = an.desc.replace("L", "").replace(";", "");
                    if (METHOD_PROTECTING_ANNOTATIONS.contains(desc)) {
                        protectedMethods.add(cn.name + "." + mn.name + mn.desc);
                        LOG.debug("Method {}.{}{} protected by @{}", cn.name, mn.name, mn.desc, desc);
                    }
                }
            }
        }

        // Check field annotations
        if (cn.fields != null) {
            for (FieldNode fn : cn.fields) {
                if (fn.visibleAnnotations != null) {
                    for (AnnotationNode an : fn.visibleAnnotations) {
                        String desc = an.desc.replace("L", "").replace(";", "");
                        if (METHOD_PROTECTING_ANNOTATIONS.contains(desc)) {
                            protectedFields.add(cn.name + "." + fn.name);
                            LOG.debug("Field {}.{} protected by @{}", cn.name, fn.name, desc);
                        }
                    }
                }
            }
        }
    }

    public boolean isMethodProtected(String className, String methodName, String methodDesc) {
        return protectedMethods.contains(className + "." + methodName + methodDesc);
    }

    public boolean isFieldProtected(String className, String fieldName) {
        return protectedFields.contains(className + "." + fieldName);
    }

    public boolean isClassProtected(String className) {
        return protectedClasses.contains(className);
    }

    public Set<String> getProtectedMethods() {
        return Collections.unmodifiableSet(protectedMethods);
    }

    public Set<String> getProtectedFields() {
        return Collections.unmodifiableSet(protectedFields);
    }

    public Set<String> getProtectedClasses() {
        return Collections.unmodifiableSet(protectedClasses);
    }

    public void addExemptAnnotation(String annotationDesc) {
        METHOD_PROTECTING_ANNOTATIONS.add(annotationDesc);
    }

    public void addExemptMethod(String className, String methodName, String methodDesc) {
        protectedMethods.add(className + "." + methodName + methodDesc);
    }

    public void addExemptField(String className, String fieldName) {
        protectedFields.add(className + "." + fieldName);
    }

    public void addExemptClass(String className) {
        protectedClasses.add(className);
    }
}
