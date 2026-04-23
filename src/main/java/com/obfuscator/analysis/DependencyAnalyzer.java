package com.obfuscator.analysis;

import com.obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * DependencyAnalyzer — анализирует зависимости между классами
 * Строит граф зависимостей для безопасной обфускации
 */
public class DependencyAnalyzer implements AnalysisPhase {
    private static final Logger logger = LoggerFactory.getLogger(DependencyAnalyzer.class);

    private final ClassPool classPool;
    
    // Граф зависимостей: класс → классы которые он использует
    private final Map<String, Set<String>> dependencies = new HashMap<>();
    
    // Обратный граф: класс → классы которые его используют
    private final Map<String, Set<String>> dependents = new HashMap<>();

    public DependencyAnalyzer(ClassPool classPool) {
        this.classPool = classPool;
    }

    @Override
    public void analyze() {
        logger.info("Analyzing class dependencies...");

        for (ClassNode classNode : classPool.getObfuscatableClasses()) {
            String className = classNode.name;
            dependencies.put(className, new HashSet<>());
            dependents.put(className, new HashSet<>());

            // Analyze superclass
            if (classNode.superName != null && !classNode.superName.equals("java/lang/Object")) {
                addDependency(className, classNode.superName);
            }

            // Analyze interfaces
            if (classNode.interfaces != null) {
                for (Object iface : classNode.interfaces) {
                    addDependency(className, (String) iface);
                }
            }

            // Analyze fields
            if (classNode.fields != null) {
                for (FieldNode field : classNode.fields) {
                    if (field.desc != null) {
                        extractTypeReferences(className, field.desc);
                    }
                    if (field.signature != null) {
                        extractSignatureReferences(className, field.signature);
                    }
                }
            }

            // Analyze methods
            if (classNode.methods != null) {
                for (MethodNode method : classNode.methods) {
                    // Method descriptor
                    if (method.desc != null) {
                        extractTypeReferences(className, method.desc);
                    }
                    if (method.signature != null) {
                        extractSignatureReferences(className, method.signature);
                    }

                    // Method instructions
                    if (method.instructions != null) {
                        for (AbstractInsnNode insn : method.instructions) {
                            String referencedType = null;
                            int opcode = insn.getOpcode();
                            
                            if (opcode == Opcodes.NEW) {
                                TypeInsnNode typeInsn = (TypeInsnNode) insn;
                                referencedType = typeInsn.desc;
                            } else if (opcode == Opcodes.INVOKEVIRTUAL || 
                                       opcode == Opcodes.INVOKESPECIAL ||
                                       opcode == Opcodes.INVOKESTATIC ||
                                       opcode == Opcodes.INVOKEINTERFACE) {
                                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                                referencedType = methodInsn.owner;
                            } else if (opcode == Opcodes.GETFIELD ||
                                       opcode == Opcodes.PUTFIELD ||
                                       opcode == Opcodes.GETSTATIC ||
                                       opcode == Opcodes.PUTSTATIC) {
                                FieldInsnNode fieldInsn = (FieldInsnNode) insn;
                                referencedType = fieldInsn.owner;
                            } else if (opcode == Opcodes.INSTANCEOF ||
                                       opcode == Opcodes.CHECKCAST) {
                                TypeInsnNode typeInsn = (TypeInsnNode) insn;
                                referencedType = typeInsn.desc;
                            } else if (opcode == Opcodes.LDC) {
                                if (insn instanceof LdcInsnNode ldc) {
                                    if (ldc.cst instanceof org.objectweb.asm.Type type) {
                                        referencedType = type.getInternalName();
                                    }
                                }
                            } else if (opcode == Opcodes.INVOKEDYNAMIC) {
                                InvokeDynamicInsnNode invokeInsn = (InvokeDynamicInsnNode) insn;
                                // Extract types from bootstrap method
                                for (Object arg : invokeInsn.bsmArgs) {
                                    if (arg instanceof org.objectweb.asm.Type type) {
                                        extractTypeReferences(className, type.getDescriptor());
                                    }
                                }
                            }

                            if (referencedType != null) {
                                addDependency(className, referencedType);
                            }
                        }
                    }
                }
            }
        }

        logger.info("Found {} classes with dependencies", dependencies.size());
    }

    private void addDependency(String from, String to) {
        if (!classPool.isMainClass(to)) {
            // External dependency (library)
            return;
        }
        
        dependencies.computeIfAbsent(from, k -> new HashSet<>()).add(to);
        dependents.computeIfAbsent(to, k -> new HashSet<>()).add(from);
    }

    private void extractTypeReferences(String className, String descriptor) {
        if (descriptor == null) return;
        
        // Parse descriptor for type references
        int i = 0;
        while (i < descriptor.length()) {
            char c = descriptor.charAt(i);
            if (c == 'L') {
                int end = descriptor.indexOf(';', i);
                if (end > i) {
                    String typeName = descriptor.substring(i + 1, end);
                    addDependency(className, typeName);
                    i = end + 1;
                } else {
                    i++;
                }
            } else if (c == '[') {
                i++;
            } else {
                i++;
            }
        }
    }

    private void extractSignatureReferences(String className, String signature) {
        if (signature == null) return;
        
        // Generic signature parsing (simplified)
        int start = 0;
        while ((start = signature.indexOf('L', start)) != -1) {
            int end = signature.indexOf(';', start);
            if (end > start) {
                String typeName = signature.substring(start + 1, end);
                // Remove any generic bounds
                int bracketIdx = typeName.indexOf('<');
                if (bracketIdx >= 0) {
                    typeName = typeName.substring(0, bracketIdx);
                }
                addDependency(className, typeName);
                start = end + 1;
            } else {
                start++;
            }
        }
    }

    /**
     * Получить все классы которые зависят от данного класса
     */
    public Set<String> getDependents(String className) {
        return Collections.unmodifiableSet(dependents.getOrDefault(className, Collections.emptySet()));
    }

    /**
     * Получить все классы от которых зависит данный класс
     */
    public Set<String> getDependencies(String className) {
        return Collections.unmodifiableSet(dependencies.getOrDefault(className, Collections.emptySet()));
    }

    /**
     * Проверить есть ли циклические зависимости
     */
    public boolean hasCyclicDependencies() {
        // Simple cycle detection using DFS
        Set<String> visited = new HashSet<>();
        Set<String> recStack = new HashSet<>();

        for (String className : dependencies.keySet()) {
            if (hasCycleDFS(className, visited, recStack)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasCycleDFS(String node, Set<String> visited, Set<String> recStack) {
        if (recStack.contains(node)) {
            return true;
        }
        if (visited.contains(node)) {
            return false;
        }

        visited.add(node);
        recStack.add(node);

        for (String neighbor : dependencies.getOrDefault(node, Collections.emptySet())) {
            if (hasCycleDFS(neighbor, visited, recStack)) {
                return true;
            }
        }

        recStack.remove(node);
        return false;
    }

    /**
     * Получить порядок обфускации (топологическая сортировка)
     * Классы без зависимостей должны быть обработаны первыми
     */
    public List<String> getObfuscationOrder() {
        List<String> result = new ArrayList<>();
        Set<String> visited = new HashSet<>();

        for (String className : dependencies.keySet()) {
            topoSort(className, visited, result);
        }

        Collections.reverse(result);
        return result;
    }

    private void topoSort(String node, Set<String> visited, List<String> result) {
        if (visited.contains(node)) {
            return;
        }

        visited.add(node);

        for (String neighbor : dependencies.getOrDefault(node, Collections.emptySet())) {
            topoSort(neighbor, visited, result);
        }

        result.add(node);
    }

    @Override
    public String getName() {
        return "DependencyAnalyzer";
    }
}
