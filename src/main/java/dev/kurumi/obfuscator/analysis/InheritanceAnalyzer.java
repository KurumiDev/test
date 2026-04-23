package dev.kurumi.obfuscator.analysis;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Computes the inheritance closure of every class in the pool so the renamer
 * can safely refuse to rename methods that originate in (or override) an
 * external type.
 */
public class InheritanceAnalyzer implements Transformer {

    /** internal name -> direct parents (super + interfaces). */
    private final Map<String, Set<String>> parents = new HashMap<>();
    /** internal name -> transitive closure including self. */
    private final Map<String, Set<String>> ancestorsCache = new HashMap<>();

    @Override
    public String name() {
        return "inheritance-analyzer";
    }

    @Override
    public boolean isEnabled(ObfuscatorConfig cfg) {
        return true;
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        parents.clear();
        ancestorsCache.clear();
        for (ClassNode cn : pool.allClassNodes()) {
            record(cn);
        }
        for (ClassNode cn : pool.libraryClasses().values()) {
            record(cn);
        }
        ctx.setInheritance(this);
    }

    private void record(ClassNode cn) {
        Set<String> direct = new LinkedHashSet<>();
        if (cn.superName != null) direct.add(cn.superName);
        if (cn.interfaces != null) direct.addAll(cn.interfaces);
        parents.put(cn.name, direct);
    }

    /** All ancestors of {@code internalName}, including self. */
    public Set<String> ancestors(String internalName) {
        Set<String> cached = ancestorsCache.get(internalName);
        if (cached != null) return cached;
        Set<String> seen = new LinkedHashSet<>();
        Deque<String> stack = new ArrayDeque<>();
        stack.push(internalName);
        while (!stack.isEmpty()) {
            String cur = stack.pop();
            if (!seen.add(cur)) continue;
            Set<String> ps = parents.get(cur);
            if (ps != null) {
                for (String p : ps) stack.push(p);
            }
        }
        ancestorsCache.put(internalName, seen);
        return seen;
    }

    /**
     * True if {@code internalName} or any of its ancestors is external to the
     * pool (i.e. declared in a JDK/library JAR that we will never transform).
     */
    public boolean hasExternalAncestor(String internalName, ClassPool pool) {
        for (String a : ancestors(internalName)) {
            if (a.equals(internalName)) continue;
            if (!pool.classes().containsKey(a)) return true;
        }
        return false;
    }

    /**
     * True if a method with the given {@code name+desc} is declared on an
     * external ancestor of {@code internalName}. Used to protect virtual
     * overrides of JDK / Bukkit / Fabric API methods.
     */
    public boolean overridesExternal(String internalName, String name, String desc, ClassPool pool) {
        for (String a : ancestors(internalName)) {
            if (a.equals(internalName)) continue;
            if (pool.classes().containsKey(a)) continue; // part of our pool
            ClassNode lib = pool.libraryClasses().get(a);
            if (lib == null) {
                // External class we cannot inspect; assume the method might exist
                // there. This is the safe choice: false positives cost us some
                // renaming, false negatives break runtime dispatch.
                return true;
            }
            for (MethodNode m : lib.methods) {
                if (m.name.equals(name) && m.desc.equals(desc)) return true;
            }
        }
        return false;
    }

    /** Build a set of methods that must not be renamed due to external API. */
    public Set<String> computeUntouchableMethods(ClassPool pool) {
        Set<String> protectedMethods = new HashSet<>();
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if ((mn.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) continue;
                if (mn.name.startsWith("<")) continue;
                if (overridesExternal(cn.name, mn.name, mn.desc, pool)) {
                    protectedMethods.add(mn.name + mn.desc);
                }
            }
        }
        return protectedMethods;
    }
}
