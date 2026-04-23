package com.obfuscator.analysis;

import com.obfuscator.core.ClassPool;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * AnnotationScanner — сканирует аннотации для определения элементов которые нельзя обфусцировать
 */
public class AnnotationScanner implements AnalysisPhase {
    private static final Logger logger = LoggerFactory.getLogger(AnnotationScanner.class);

    private final ClassPool classPool;

    // Классы с аннотациями
    private final Map<String, Set<String>> annotatedClasses = new HashMap<>();

    // Методы с аннотациями: className#methodName+desc → annotations
    private final Map<String, Set<String>> annotatedMethods = new HashMap<>();

    // Поля с аннотациями: className#fieldName → annotations
    private final Map<String, Set<String>> annotatedFields = new HashMap<>();

    // Все уникальные аннотации найденные в проекте
    private final Set<String> allAnnotations = new HashSet<>();

    public AnnotationScanner(ClassPool classPool) {
        this.classPool = classPool;
    }

    @Override
    public void analyze() {
        logger.info("Scanning annotations...");

        for (ClassNode classNode : classPool.getObfuscatableClasses()) {
            String className = classNode.name;

            // Scan class annotations
            if (classNode.visibleAnnotations != null) {
                Set<String> classAnnots = new HashSet<>();
                for (AnnotationNode annot : classNode.visibleAnnotations) {
                    String desc = annot.desc;
                    classAnnots.add(desc);
                    allAnnotations.add(desc);
                }
                annotatedClasses.put(className, classAnnots);
            }

            // Scan field annotations
            if (classNode.fields != null) {
                for (FieldNode field : classNode.fields) {
                    if (field.visibleAnnotations != null && !field.visibleAnnotations.isEmpty()) {
                        String key = className + "#" + field.name;
                        Set<String> fieldAnnots = new HashSet<>();
                        for (AnnotationNode annot : field.visibleAnnotations) {
                            String desc = annot.desc;
                            fieldAnnots.add(desc);
                            allAnnotations.add(desc);
                        }
                        annotatedFields.put(key, fieldAnnots);
                    }
                }
            }

            // Scan method annotations
            if (classNode.methods != null) {
                for (MethodNode method : classNode.methods) {
                    Set<String> methodAnnots = new HashSet<>();

                    if (method.visibleAnnotations != null) {
                        for (AnnotationNode annot : method.visibleAnnotations) {
                            String desc = annot.desc;
                            methodAnnots.add(desc);
                            allAnnotations.add(desc);
                        }
                    }

                    // Also scan parameter annotations (for @EventHandler in some cases)
                    if (method.visibleParameterAnnotations != null) {
                        for (var paramAnnots : method.visibleParameterAnnotations) {
                            if (paramAnnots != null) {
                                for (AnnotationNode annot : paramAnnots) {
                                    String desc = annot.desc;
                                    methodAnnots.add(desc);
                                    allAnnotations.add(desc);
                                }
                            }
                        }
                    }

                    if (!methodAnnots.isEmpty()) {
                        String key = className + "#" + method.name + method.desc;
                        annotatedMethods.put(key, methodAnnots);
                    }
                }
            }
        }

        logger.info("Found {} annotated classes, {} annotated methods, {} annotated fields",
                annotatedClasses.size(), annotatedMethods.size(), annotatedFields.size());
        logger.info("Unique annotations found: {}", allAnnotations.size());
    }

    /**
     * Проверить имеет ли класс указанную аннотацию
     */
    public boolean hasAnnotation(String className, String annotationDesc) {
        Set<String> annots = annotatedClasses.get(className);
        return annots != null && annots.contains(annotationDesc);
    }

    /**
     * Проверить имеет ли метод указанную аннотацию
     */
    public boolean hasMethodAnnotation(String className, String methodName, String methodDesc, String annotationDesc) {
        String key = className + "#" + methodName + methodDesc;
        Set<String> annots = annotatedMethods.get(key);
        return annots != null && annots.contains(annotationDesc);
    }

    /**
     * Проверить имеет ли поле указанную аннотацию
     */
    public boolean hasFieldAnnotation(String className, String fieldName, String annotationDesc) {
        String key = className + "#" + fieldName;
        Set<String> annots = annotatedFields.get(key);
        return annots != null && annots.contains(annotationDesc);
    }

    /**
     * Получить все аннотации класса
     */
    public Set<String> getClassAnnotations(String className) {
        return Collections.unmodifiableSet(annotatedClasses.getOrDefault(className, Collections.emptySet()));
    }

    /**
     * Получить все аннотации метода
     */
    public Set<String> getMethodAnnotations(String className, String methodName, String methodDesc) {
        String key = className + "#" + methodName + methodDesc;
        return Collections.unmodifiableSet(annotatedMethods.getOrDefault(key, Collections.emptySet()));
    }

    /**
     * Получить все аннотации поля
     */
    public Set<String> getFieldAnnotations(String className, String fieldName) {
        String key = className + "#" + fieldName;
        return Collections.unmodifiableSet(annotatedFields.getOrDefault(key, Collections.emptySet()));
    }

    /**
     * Проверить защищён ли класс от переименования по аннотациям
     */
    public boolean isClassExempt(String className, Set<String> exemptAnnotations) {
        Set<String> annots = getClassAnnotations(className);
        for (String exempt : exemptAnnotations) {
            if (annots.contains(exempt)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверить защищён ли метод от переименования по аннотациям
     */
    public boolean isMethodExempt(String className, String methodName, String methodDesc, 
                                   Set<String> exemptAnnotations) {
        Set<String> annots = getMethodAnnotations(className, methodName, methodDesc);
        for (String exempt : exemptAnnotations) {
            if (annots.contains(exempt)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Проверить защищено ли поле от переименования по аннотациям
     */
    public boolean isFieldExempt(String className, String fieldName, Set<String> exemptAnnotations) {
        Set<String> annots = getFieldAnnotations(className, fieldName);
        for (String exempt : exemptAnnotations) {
            if (annots.contains(exempt)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Найти все методы с @EventHandler аннотацией (Bukkit)
     */
    public Set<String> findEventHandlers() {
        Set<String> handlers = new HashSet<>();
        String eventHandlerAnnot = "Lorg/bukkit/event/EventHandler;";

        for (var entry : annotatedMethods.entrySet()) {
            if (entry.getValue().contains(eventHandlerAnnot)) {
                handlers.add(entry.getKey());
            }
        }

        return handlers;
    }

    /**
     * Найти все поля с @SerializedName аннотацией (Gson)
     */
    public Set<String> findSerializedFields() {
        Set<String> serialized = new HashSet<>();
        String serializedNameAnnot = "Lcom/google/gson/annotations/SerializedName;";

        for (var entry : annotatedFields.entrySet()) {
            if (entry.getValue().contains(serializedNameAnnot)) {
                serialized.add(entry.getKey());
            }
        }

        return serialized;
    }

    /**
     * Получить все найденные аннотации
     */
    public Set<String> getAllAnnotations() {
        return Collections.unmodifiableSet(allAnnotations);
    }

    @Override
    public String getName() {
        return "AnnotationScanner";
    }
}
