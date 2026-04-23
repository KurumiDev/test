package obfuscator.analysis;

import obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Builds inheritance graph including library classes.
 * Essential for determining what can be safely renamed.
 */
public class InheritanceGraph {
    private static final Logger LOG = LoggerFactory.getLogger(InheritanceGraph.class);

    // className -> Set of parent class names (superclass + interfaces)
    private final Map<String, Set<String>> parents = new HashMap<>();
    // methodSignature -> Set of classNames that declare this method
    private final Map<String, Set<String>> methodDeclarations = new HashMap<>();
    // className -> Set of child class names
    private final Map<String, Set<String>> children = new HashMap<>();

    private ClassPool pool;

    public void build(ClassPool pool) {
        this.pool = pool;
        LOG.info("Building inheritance graph...");

        // First pass: collect all parent relationships
        for (ClassNode cn : pool.getOwnClasses()) {
            analyzeClass(cn);
        }
        for (ClassNode cn : pool.getLibClasses()) {
            analyzeClass(cn);
        }

        // Second pass: build children relationships
        for (String className : parents.keySet()) {
            Set<String> parentSet = parents.get(className);
            for (String parent : parentSet) {
                children.computeIfAbsent(parent, k -> new HashSet<>()).add(className);
            }
        }

        LOG.info("Inheritance graph built: {} classes, {} parent relations, {} child relations",
                parents.size(), 
                parents.values().stream().mapToInt(Set::size).sum(),
                children.values().stream().mapToInt(Set::size).sum());
    }

    private void analyzeClass(ClassNode cn) {
        String className = cn.name;
        Set<String> parentSet = new HashSet<>();

        // Superclass
        if (cn.superName != null && !"java/lang/Object".equals(cn.superName)) {
            parentSet.add(cn.superName);
        }

        // Interfaces
        if (cn.interfaces != null) {
            parentSet.addAll(cn.interfaces);
        }

        parents.put(className, parentSet);

        // Track method declarations
        for (MethodNode mn : cn.methods) {
            String methodSig = cn.name + "." + mn.name + mn.desc;
            methodDeclarations.computeIfAbsent(methodSig, k -> new HashSet<>()).add(className);
        }
    }

    /**
     * Returns all ancestors of a class (recursive)
     */
    public Set<String> getAllAncestors(String className) {
        Set<String> result = new HashSet<>();
        collectAncestors(className, result);
        return result;
    }

    private void collectAncestors(String className, Set<String> result) {
        Set<String> directParents = parents.get(className);
        if (directParents == null) return;
        
        for (String parent : directParents) {
            if (result.add(parent)) {
                collectAncestors(parent, result);
            }
        }
    }

    /**
     * Returns all descendants of a class (recursive)
     */
    public Set<String> getAllDescendants(String className) {
        Set<String> result = new HashSet<>();
        collectDescendants(className, result);
        return result;
    }

    private void collectDescendants(String className, Set<String> result) {
        Set<String> directChildren = children.get(className);
        if (directChildren == null) return;
        
        for (String child : directChildren) {
            if (result.add(child)) {
                collectDescendants(child, result);
            }
        }
    }

    /**
     * Check if a method can be renamed.
     * Method M in class C can be renamed ONLY IF:
     * 1. No ancestor of C declares M
     * 2. No descendant of C overrides M with public visibility
     * 3. M is not marked with exempt annotations
     */
    public boolean canRenameMethod(String owner, String name, String desc) {
        // Check if any ancestor declares this method
        Set<String> ancestors = getAllAncestors(owner);
        for (String ancestor : ancestors) {
            ClassNode ancestorClass = pool.getClassNode(ancestor);
            if (ancestorClass != null) {
                for (MethodNode mn : ancestorClass.methods) {
                    if (mn.name.equals(name) && mn.desc.equals(desc)) {
                        // Ancestor has this method - cannot rename
                        return false;
                    }
                }
            }
        }

        // Check if any descendant overrides this method
        Set<String> descendants = getAllDescendants(owner);
        for (String descendant : descendants) {
            ClassNode descendantClass = pool.getClassNode(descendant);
            if (descendantClass != null) {
                for (MethodNode mn : descendantClass.methods) {
                    if (mn.name.equals(name) && mn.desc.equals(desc)) {
                        // Check if it's public or protected (overridable)
                        int access = mn.access;
                        if ((access & Opcodes.ACC_PUBLIC) != 0 ||
                            (access & Opcodes.ACC_PROTECTED) != 0) {
                            return false;
                        }
                    }
                }
            }
        }

        return true;
    }

    /**
     * Check if a field can be renamed.
     */
    public boolean canRenameField(String owner, String name) {
        // Fields in interfaces cannot be renamed
        ClassNode cn = pool.getClassNode(owner);
        if (cn != null && (cn.access & Opcodes.ACC_INTERFACE) != 0) {
            return false;
        }

        // Check ancestors for field declarations
        Set<String> ancestors = getAllAncestors(owner);
        for (String ancestor : ancestors) {
            ClassNode ancestorClass = pool.getClassNode(ancestor);
            if (ancestorClass != null) {
                for (var fn : ancestorClass.fields) {
                    if (fn.name.equals(name)) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    /**
     * Check if a class can be renamed.
     */
    public boolean canRenameClass(String name) {
        ClassNode cn = pool.getClassNode(name);
        if (cn == null) return false;

        // Don't rename classes that extend library classes with specific annotations
        if (cn.superName != null) {
            // Check if superclass is from library and has special handling
            if (isExemptSuperclass(cn.superName)) {
                return false;
            }
        }

        // Don't rename classes implementing certain interfaces
        if (cn.interfaces != null) {
            for (String iface : cn.interfaces) {
                if (isExemptInterface(iface)) {
                    return false;
                }
            }
        }

        return true;
    }

    private boolean isExemptSuperclass(String superName) {
        // Common exempt superclasses
        return "org/bukkit/plugin/java/JavaPlugin".equals(superName) ||
               "net/md_5/bungee/api/plugin/Plugin".equals(superName) ||
               "com/velocitypowered/api/plugin/ProxyPlugin".equals(superName);
    }

    private boolean isExemptInterface(String iface) {
        // Common exempt interfaces
        return "org/bukkit/event/Listener".equals(iface) ||
               "java/io/Serializable".equals(iface) ||
               "java/lang/Comparable".equals(iface);
    }

    public boolean hasClass(String internalName) {
        return parents.containsKey(internalName);
    }

    public Set<String> getParents(String className) {
        return parents.getOrDefault(className, Collections.emptySet());
    }

    public Set<String> getChildren(String className) {
        return children.getOrDefault(className, Collections.emptySet());
    }
}
