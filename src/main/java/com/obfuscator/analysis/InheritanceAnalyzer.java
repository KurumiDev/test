package com.obfuscator.analysis;

import com.obfuscator.core.ClassPool;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * InheritanceAnalyzer — анализирует иерархию классов
 * Критично для безопасного переименования методов
 */
public class InheritanceAnalyzer implements AnalysisPhase {
    private static final Logger logger = LoggerFactory.getLogger(InheritanceAnalyzer.class);

    private final ClassPool classPool;

    // Класс → все его суперклассы (включая непрямые)
    private final Map<String, Set<String>> allSuperclasses = new HashMap<>();

    // Класс → все его подклассы
    private final Map<String, Set<String>> allSubclasses = new HashMap<>();

    // Класс → реализованные интерфейсы
    private final Map<String, Set<String>> implementedInterfaces = new HashMap<>();

    // Методы которые НЕЛЬЗЯ переименовывать (переопределяют внешние методы)
    private final Set<String> nonRenamableMethods = new HashSet<>();

    public InheritanceAnalyzer(ClassPool classPool) {
        this.classPool = classPool;
    }

    @Override
    public void analyze() {
        logger.info("Analyzing class inheritance...");

        // Phase 1: Build direct inheritance relationships
        for (ClassNode classNode : classPool.getObfuscatableClasses()) {
            String className = classNode.name;

            // Superclass
            if (classNode.superName != null && !classNode.superName.equals("java/lang/Object")) {
                allSuperclasses.computeIfAbsent(className, k -> new HashSet<>()).add(classNode.superName);
                allSubclasses.computeIfAbsent(classNode.superName, k -> new HashSet<>()).add(className);
            }

            // Interfaces
            Set<String> interfaces = new HashSet<>();
            if (classNode.interfaces != null) {
                for (Object iface : classNode.interfaces) {
                    String ifaceName = (String) iface;
                    interfaces.add(ifaceName);
                    implementedInterfaces.put(className, interfaces);
                }
            }
        }

        // Phase 2: Compute transitive closures
        computeTransitiveSuperclasses();

        // Phase 3: Find non-renamable methods
        findNonRenamableMethods();

        logger.info("Found {} classes with inheritance data", allSuperclasses.size());
        logger.info("Found {} non-renamable methods", nonRenamableMethods.size());
    }

    private void computeTransitiveSuperclasses() {
        for (String className : allSuperclasses.keySet()) {
            Set<String> supers = new HashSet<>(allSuperclasses.get(className));
            
            boolean changed = true;
            while (changed) {
                changed = false;
                Set<String> newSupers = new HashSet<>(supers);
                
                for (String superName : supers) {
                    Set<String> superSupers = allSuperclasses.get(superName);
                    if (superSupers != null) {
                        for (String ss : superSupers) {
                            if (!newSupers.contains(ss)) {
                                newSupers.add(ss);
                                changed = true;
                            }
                        }
                    }
                }
                
                supers = newSupers;
            }
            
            allSuperclasses.put(className, supers);
        }
    }

    private void findNonRenamableMethods() {
        for (ClassNode classNode : classPool.getObfuscatableClasses()) {
            String className = classNode.name;

            // Check if class extends external class
            boolean hasExternalSuperclass = false;
            if (classNode.superName != null && !classNode.superName.equals("java/lang/Object")) {
                if (!classPool.isMainClass(classNode.superName)) {
                    hasExternalSuperclass = true;
                }
            }

            // Check if class implements external interfaces
            List<String> externalInterfaces = new ArrayList<>();
            if (classNode.interfaces != null) {
                for (Object iface : classNode.interfaces) {
                    String ifaceName = (String) iface;
                    if (!classPool.isMainClass(ifaceName)) {
                        externalInterfaces.add(ifaceName);
                    }
                }
            }

            // If class has external superclass or interfaces, mark overriding methods as non-renamable
            if (hasExternalSuperclass || !externalInterfaces.isEmpty()) {
                for (var method : classNode.methods) {
                    String methodSig = method.name + method.desc;
                    
                    // Check if this method overrides something from external class/interface
                    if (overridesExternalMethod(classNode, method, hasExternalSuperclass, externalInterfaces)) {
                        nonRenamableMethods.add(className + "#" + methodSig);
                    }
                }
            }
        }
    }

    private boolean overridesExternalMethod(ClassNode classNode, org.objectweb.asm.tree.MethodNode method,
                                            boolean hasExternalSuperclass, List<String> externalInterfaces) {
        // Skip constructors and static methods
        if (method.name.equals("<init>") || method.name.equals("<clinit>")) {
            return false;
        }
        if ((method.access & org.objectweb.asm.Opcodes.ACC_STATIC) != 0) {
            return false;
        }

        // Check external superclass
        if (hasExternalSuperclass && classNode.superName != null) {
            ClassNode superClass = classPool.getClassNode(classNode.superName);
            if (superClass != null) {
                for (var superMethod : superClass.methods) {
                    if (superMethod.name.equals(method.name) && superMethod.desc.equals(method.desc)) {
                        return true;
                    }
                }
            }
        }

        // Check external interfaces
        for (String ifaceName : externalInterfaces) {
            ClassNode iface = classPool.getClassNode(ifaceName);
            if (iface != null) {
                for (var ifaceMethod : iface.methods) {
                    if (ifaceMethod.name.equals(method.name) && ifaceMethod.desc.equals(method.desc)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Получить все суперклассы класса (включая непрямые)
     */
    public Set<String> getAllSuperclasses(String className) {
        return Collections.unmodifiableSet(allSuperclasses.getOrDefault(className, Collections.emptySet()));
    }

    /**
     * Получить все подклассы класса
     */
    public Set<String> getAllSubclasses(String className) {
        return Collections.unmodifiableSet(allSubclasses.getOrDefault(className, Collections.emptySet()));
    }

    /**
     * Получить все реализованные интерфейсы
     */
    public Set<String> getImplementedInterfaces(String className) {
        return Collections.unmodifiableSet(implementedInterfaces.getOrDefault(className, Collections.emptySet()));
    }

    /**
     * Проверить можно ли переименовать метод
     */
    public boolean canRenameMethod(String className, String methodName, String methodDesc) {
        String sig = className + "#" + methodName + methodDesc;
        return !nonRenamableMethods.contains(sig);
    }

    /**
     * Получить список всех не-переименовываемых методов
     */
    public Set<String> getNonRenamableMethods() {
        return Collections.unmodifiableSet(nonRenamableMethods);
    }

    /**
     * Проверить является ли класс подклассом другого
     */
    public boolean isSubclassOf(String className, String superClassName) {
        return getAllSuperclasses(className).contains(superClassName);
    }

    /**
     * Получить корневой суперкласс (не Object)
     */
    public String getRootSuperclass(String className) {
        Set<String> supers = getAllSuperclasses(className);
        if (supers.isEmpty()) {
            return null;
        }
        
        String root = className;
        for (String superName : supers) {
            if (!getAllSuperclasses(superName).isEmpty()) {
                root = superName;
            }
        }
        return root;
    }

    @Override
    public String getName() {
        return "InheritanceAnalyzer";
    }
}
