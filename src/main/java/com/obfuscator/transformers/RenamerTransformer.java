package com.obfuscator.transformers;

import com.obfuscator.analysis.AnnotationScanner;
import com.obfuscator.analysis.InheritanceAnalyzer;
import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import com.obfuscator.util.NameGenerator;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * RenamerTransformer — переименовывает классы, методы и поля
 * САМЫЙ ВАЖНЫЙ трансформер
 * 
 * Стратегии именования:
 * - ALPHABET   → a, b, c, ..., aa, ab, ...
 * - UNICODE    → \u0001\u0002 (ломает большинство декомпиляторов)
 * - CONFUSE    → Il1IlIl (визуально неразличимые символы)
 * - RANDOM_HEX → a3f2b1c (выглядит как хеш)
 */
public class RenamerTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(RenamerTransformer.class);

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    // Mapping: старое имя → новое имя
    private final Map<String, String> classMapping = new HashMap<>();
    private final Map<String, Map<String, String>> methodMapping = new HashMap<>();
    private final Map<String, Map<String, String>> fieldMapping = new HashMap<>();

    // Защищённые элементы (не переименовывать)
    private final Set<String> exemptClasses = new HashSet<>();
    private final Set<String> exemptMethods = new HashSet<>();
    private final Set<String> exemptFields = new HashSet<>();

    private NameGenerator nameGenerator;

    public RenamerTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        logger.info("Starting renaming with strategy: {}", config.getRenamingStrategy());

        // Initialize name generator
        nameGenerator = new NameGenerator(config.getRenamingStrategy());

        // Phase 1: Collect all exemptions
        collectExemptions();

        // Phase 2: Build mapping for classes
        buildClassMapping();

        // Phase 3: Build mapping for methods and fields
        buildMemberMapping();

        // Phase 4: Apply mappings to all classes
        applyMappings();

        // Log statistics
        logger.info("Renamed {} classes, {} methods, {} fields",
                classMapping.size(),
                methodMapping.values().stream().mapToInt(Map::size).sum(),
                fieldMapping.values().stream().mapToInt(Map::size).sum());
    }

    private void collectExemptions() {
        // Get exempt annotations from config
        Set<String> exemptAnnotations = config.getExemptAnnotations();

        // Get analyzers from pool (they should have run already)
        AnnotationScanner annotationScanner = null;
        InheritanceAnalyzer inheritanceAnalyzer = null;

        // Try to find analyzers (they're created in pipeline)
        // For now, use config exemptions directly
        
        // Add manual exemptions from config
        for (String exemption : config.getExemptions()) {
            if (exemption.startsWith("@")) {
                // Annotation-based exemption - handled by scanner
                continue;
            } else if (exemption.contains("#")) {
                // Method or field exemption
                if (exemption.contains("(")) {
                    // Method: com.example.Class#method(Ljava/lang/String;)V
                    exemptMethods.add(exemption.replace("#", "/").replace("(", "#("));
                } else {
                    // Field: com.example.Class#fieldName
                    exemptFields.add(exemption);
                }
            } else if (exemption.endsWith("**")) {
                // Package exemption
                String pkg = exemption.substring(0, exemption.length() - 2);
                for (ClassNode cn : classPool.getObfuscatableClasses()) {
                    if (cn.name.startsWith(pkg)) {
                        exemptClasses.add(cn.name);
                    }
                }
            } else {
                // Full class exemption
                String internalName = exemption.replace('.', '/');
                exemptClasses.add(internalName);
            }
        }

        // Auto-exempt based on target type
        if (config.getTargetType() == ObfuscatorConfig.TargetType.AUTO ||
            config.getTargetType() == ObfuscatorConfig.TargetType.PAPER) {
            
            // Exempt common Bukkit patterns
            for (ClassNode cn : classPool.getObfuscatableClasses()) {
                // Check if extends JavaPlugin
                if ("org/bukkit/plugin/java/JavaPlugin".equals(cn.superName)) {
                    // Exempt lifecycle methods
                    for (MethodNode m : cn.methods) {
                        if (m.name.equals("onEnable") || m.name.equals("onDisable") || m.name.equals("onLoad")) {
                            exemptMethods.add(cn.name + "/" + m.name + "#" + m.desc);
                        }
                    }
                }
            }
        }
    }

    private void buildClassMapping() {
        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            if (exemptClasses.contains(cn.name)) {
                logger.debug("Skipping exempt class: {}", cn.name);
                continue;
            }

            // Check if class is in exempt package
            boolean skip = false;
            for (String exempt : exemptClasses) {
                if (cn.name.startsWith(exempt)) {
                    skip = true;
                    break;
                }
            }
            if (skip) continue;

            String newName = nameGenerator.generateClassName();
            classMapping.put(cn.name, newName);
            logger.trace("Class mapping: {} → {}", cn.name, newName);
        }
    }

    private void buildMemberMapping() {
        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            String className = cn.name;

            // Methods
            if (config.isRenameMethods()) {
                Map<String, String> classMethodMap = new HashMap<>();
                
                for (MethodNode method : cn.methods) {
                    // Skip constructors and clinit
                    if (method.name.equals("<init>") || method.name.equals("<clinit>")) {
                        continue;
                    }

                    String methodKey = className + "/" + method.name + "#" + method.desc;
                    
                    if (exemptMethods.contains(methodKey)) {
                        logger.debug("Skipping exempt method: {}", methodKey);
                        continue;
                    }

                    // Check inheritance - can't rename overriding methods
                    // This is simplified - full implementation would check InheritanceAnalyzer
                    
                    String newName = nameGenerator.generateMethodName();
                    classMethodMap.put(method.name + method.desc, newName);
                }
                
                if (!classMethodMap.isEmpty()) {
                    methodMapping.put(className, classMethodMap);
                }
            }

            // Fields
            if (config.isRenameFields()) {
                Map<String, String> classFieldMap = new HashMap<>();
                
                for (FieldNode field : cn.fields) {
                    String fieldKey = className + "#" + field.name;
                    
                    if (exemptFields.contains(fieldKey)) {
                        logger.debug("Skipping exempt field: {}", fieldKey);
                        continue;
                    }

                    String newName = nameGenerator.generateFieldName();
                    classFieldMap.put(field.name, newName);
                }
                
                if (!classFieldMap.isEmpty()) {
                    fieldMapping.put(className, classFieldMap);
                }
            }
        }
    }

    private void applyMappings() {
        // Create remapper
        ObfuscatorRemapper remapper = new ObfuscatorRemapper(classMapping, methodMapping, fieldMapping);

        // Apply to all classes
        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            // Remap superclass
            if (cn.superName != null && classMapping.containsKey(cn.superName)) {
                cn.superName = classMapping.get(cn.superName);
            }

            // Remap interfaces
            if (cn.interfaces != null) {
                cn.interfaces = cn.interfaces.stream()
                    .map(iface -> {
                        String ifaceStr = (String) iface;
                        return classMapping.getOrDefault(ifaceStr, ifaceStr);
                    })
                    .toList();
            }

            // Remap methods
            for (MethodNode method : cn.methods) {
                remapper.visitMethod(method);
            }

            // Remap fields
            for (FieldNode field : cn.fields) {
                if (fieldMapping.containsKey(cn.name) && 
                    fieldMapping.get(cn.name).containsKey(field.name)) {
                    field.name = fieldMapping.get(cn.name).get(field.name);
                }
            }

            // Remap class name in the node itself
            if (classMapping.containsKey(cn.name)) {
                // Note: We don't change cn.name here because it's used as key in the pool
                // The actual class name change happens during write
            }
        }
    }

    /**
     * Получить mapping для сохранения в файл
     */
    public Map<String, String> getClassMapping() {
        return Collections.unmodifiableMap(classMapping);
    }

    public Map<String, Map<String, String>> getMethodMapping() {
        return Collections.unmodifiableMap(methodMapping);
    }

    public Map<String, Map<String, String>> getFieldMapping() {
        return Collections.unmodifiableMap(fieldMapping);
    }

    @Override
    public String getName() {
        return "RenamerTransformer";
    }

    /**
     * Внутренний ремapper для применения маппинга
     */
    private static class ObfuscatorRemapper extends org.objectweb.asm.commons.Remapper {
        private final Map<String, String> classMapping;
        private final Map<String, Map<String, String>> methodMapping;
        private final Map<String, Map<String, String>> fieldMapping;

        public ObfuscatorRemapper(Map<String, String> classMapping,
                                   Map<String, Map<String, String>> methodMapping,
                                   Map<String, Map<String, String>> fieldMapping) {
            this.classMapping = classMapping;
            this.methodMapping = methodMapping;
            this.methodMapping = methodMapping;
            this.fieldMapping = fieldMapping;
        }

        @Override
        public String map(String internalName) {
            return classMapping.getOrDefault(internalName, internalName);
        }

        @Override
        public String mapMethodName(String owner, String name, String desc) {
            Map<String, String> classMethods = methodMapping.get(owner);
            if (classMethods != null) {
                return classMethods.getOrDefault(name + desc, name);
            }
            return name;
        }

        @Override
        public String mapFieldName(String owner, String name, String desc) {
            Map<String, String> classFields = fieldMapping.get(owner);
            if (classFields != null) {
                return classFields.getOrDefault(name, name);
            }
            return name;
        }

        public void visitMethod(MethodNode method) {
            // Remap method instructions
            for (var insn : method.instructions) {
                int opcode = insn.getOpcode();
                
                if (opcode >= org.objectweb.asm.Opcodes.INVOKEVIRTUAL && 
                    opcode <= org.objectweb.asm.Opcodes.INVOKEINTERFACE) {
                    var methodInsn = (org.objectweb.asm.tree.MethodInsnNode) insn;
                    methodInsn.name = mapMethodName(methodInsn.owner, methodInsn.name, methodInsn.desc);
                    methodInsn.owner = map(methodInsn.owner);
                } else if (opcode == org.objectweb.asm.Opcodes.GETFIELD ||
                           opcode == org.objectweb.asm.Opcodes.PUTFIELD ||
                           opcode == org.objectweb.asm.Opcodes.GETSTATIC ||
                           opcode == org.objectweb.asm.Opcodes.PUTSTATIC) {
                    var fieldInsn = (org.objectweb.asm.tree.FieldInsnNode) insn;
                    fieldInsn.name = mapFieldName(fieldInsn.owner, fieldInsn.name, fieldInsn.desc);
                    fieldInsn.owner = map(fieldInsn.owner);
                } else if (opcode == org.objectweb.asm.Opcodes.NEW ||
                           opcode == org.objectweb.asm.Opcodes.CHECKCAST ||
                           opcode == org.objectweb.asm.Opcodes.INSTANCEOF) {
                    var typeInsn = (org.objectweb.asm.tree.TypeInsnNode) insn;
                    typeInsn.desc = map(typeInsn.desc);
                } else if (opcode == org.objectweb.asm.Opcodes.LDC) {
                    var ldcInsn = (org.objectweb.asm.tree.LdcInsnNode) insn;
                    if (ldcInsn.cst instanceof org.objectweb.asm.Type type) {
                        String mapped = map(type.getInternalName());
                        if (!mapped.equals(type.getInternalName())) {
                            ldcInsn.cst = org.objectweb.asm.Type.getType("L" + mapped + ";");
                        }
                    }
                }
            }
        }
    }
}
