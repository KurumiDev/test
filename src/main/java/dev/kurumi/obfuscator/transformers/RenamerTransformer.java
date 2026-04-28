package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.analysis.AnnotationScanner;
import dev.kurumi.obfuscator.analysis.InheritanceAnalyzer;
import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Core renamer. Handles classes, methods (virtual + static/private), fields and
 * local variables. Builds inheritance-aware equivalence classes so virtual
 * dispatch continues to work post-rename.
 */
public class RenamerTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(RenamerTransformer.class);

    @Override
    public String name() {
        return "renamer";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        ObfuscatorConfig cfg = ctx.config();
        ObfuscatorConfig.NamingStrategy strat = cfg.namingStrategy();

        Set<String> referencedInResources = scanResourceReferences(pool);

        Map<String, String> mapping = new LinkedHashMap<>();

        NameGenerator classGen = new NameGenerator(strat);
        if (cfg.renameClasses()) {
            buildClassMapping(pool, ctx, referencedInResources, classGen, mapping);
        }

        NameGenerator methodGen = new NameGenerator(strat);
        if (cfg.renameMethods()) {
            buildMethodMapping(pool, ctx, methodGen, mapping);
        }

        if (cfg.renameFields()) {
            buildFieldMapping(pool, ctx, strat, mapping);
        }

        if (mapping.isEmpty()) {
            log.info("No renames produced");
            return;
        }

        SimpleRemapper remapper = new SimpleRemapper(mapping);
        Map<String, ClassNode> replaced = new LinkedHashMap<>();
        for (ClassNode cn : pool.allClassNodes()) {
            ClassNode copy = new ClassNode();
            cn.accept(new ClassRemapper(copy, remapper));
            if (cfg.renameLocalVars()) {
                renameLocals(copy);
            }
            replaced.put(copy.name, copy);
        }
        pool.replaceClasses(replaced);

        recordMappings(mapping, ctx);
        log.info("Renamed {} classes, {} methods/fields", ctx.classMapping().size(),
                ctx.methodMapping().size() + ctx.fieldMapping().size());
    }

    /**
     * Targeted scan for class references that the JVM or host platform will
     * look up reflectively by fully-qualified name. We deliberately do NOT do
     * a "find every dotted name in every text resource" pass — that treats
     * unrelated files (pom.xml with a groupId, localized config strings) as
     * reflection pins and stops legitimate renames.
     *
     * Protected contexts:
     *   - plugin.yml / paper-plugin.yml / bungee.yml / velocity-plugin.json:
     *     "main:" (and Velocity's explicit main class field).
     *   - fabric.mod.json: entrypoints.* values (strip leading "::" or adapter prefix).
     *   - mods.toml / neoforge.mods.toml: not required (@Mod handles it),
     *     but we still honour a "mainClass=" line if present.
     *   - META-INF/services/*: every non-blank, non-comment line is a FQN.
     *   - META-INF/MANIFEST.MF: Main-Class, Premain-Class, Agent-Class.
     */
    private Set<String> scanResourceReferences(ClassPool pool) {
        Set<String> referenced = new HashSet<>();
        Set<String> internalSet = pool.classes().keySet();
        for (Map.Entry<String, byte[]> e : pool.resources().entrySet()) {
            String name = e.getKey();
            byte[] body = e.getValue();
            String lower = name.toLowerCase();

            if (name.startsWith("META-INF/services/")) {
                String svcName = name.substring("META-INF/services/".length());
                // the service name itself is a FQN
                pinIfPresent(internalSet, svcName, referenced);
                for (String line : utf8Lines(body)) {
                    line = stripComment(line).trim();
                    if (!line.isEmpty()) pinIfPresent(internalSet, line, referenced);
                }
                continue;
            }

            if ("META-INF/MANIFEST.MF".equalsIgnoreCase(name)) {
                for (String line : utf8Lines(body)) {
                    String v = stripManifestKey(line, "Main-Class");
                    if (v == null) v = stripManifestKey(line, "Premain-Class");
                    if (v == null) v = stripManifestKey(line, "Agent-Class");
                    if (v != null) pinIfPresent(internalSet, v.trim(), referenced);
                }
                continue;
            }

            if (lower.endsWith("plugin.yml") || lower.endsWith("paper-plugin.yml")
                    || lower.endsWith("bungee.yml")) {
                for (String line : utf8Lines(body)) {
                    String v = stripYamlKey(line, "main");
                    if (v != null) pinIfPresent(internalSet, v, referenced);
                }
                continue;
            }

            if (lower.endsWith("velocity-plugin.json") || lower.endsWith("fabric.mod.json")) {
                // cheap JSON walk — not a full parser, but good enough for "main":"FQN" and entrypoint arrays
                String content = new String(body, StandardCharsets.UTF_8);
                for (String quoted : jsonStringValues(content)) {
                    String candidate = quoted;
                    int colon = candidate.indexOf("::");
                    if (colon >= 0) candidate = candidate.substring(0, colon);
                    if (candidate.contains("::")) continue;
                    pinIfPresent(internalSet, candidate.trim(), referenced);
                }
                continue;
            }

            if (lower.endsWith("mods.toml") || lower.endsWith("neoforge.mods.toml")) {
                for (String line : utf8Lines(body)) {
                    String v = stripTomlKey(line, "mainClass");
                    if (v != null) pinIfPresent(internalSet, v, referenced);
                }
            }
        }
        return referenced;
    }

    private static void pinIfPresent(Set<String> classes, String dotted, Set<String> out) {
        if (dotted == null || dotted.isEmpty()) return;
        String internal = dotted.replace('.', '/');
        if (classes.contains(internal)) out.add(internal);
    }

    private static List<String> utf8Lines(byte[] data) {
        return List.of(new String(data, StandardCharsets.UTF_8).split("\\r?\\n", -1));
    }

    private static String stripComment(String s) {
        int hash = s.indexOf('#');
        return hash < 0 ? s : s.substring(0, hash);
    }

    private static String stripManifestKey(String line, String key) {
        int colon = line.indexOf(':');
        if (colon < 0) return null;
        if (!line.substring(0, colon).trim().equalsIgnoreCase(key)) return null;
        return line.substring(colon + 1).trim();
    }

    private static String stripYamlKey(String line, String key) {
        String t = stripComment(line);
        int colon = t.indexOf(':');
        if (colon < 0) return null;
        if (!t.substring(0, colon).trim().equalsIgnoreCase(key)) return null;
        String v = t.substring(colon + 1).trim();
        if ((v.startsWith("\"") && v.endsWith("\"") && v.length() >= 2)
                || (v.startsWith("'") && v.endsWith("'") && v.length() >= 2)) {
            v = v.substring(1, v.length() - 1);
        }
        return v;
    }

    private static String stripTomlKey(String line, String key) {
        String t = stripComment(line);
        int eq = t.indexOf('=');
        if (eq < 0) return null;
        if (!t.substring(0, eq).trim().equalsIgnoreCase(key)) return null;
        String v = t.substring(eq + 1).trim();
        if ((v.startsWith("\"") && v.endsWith("\"") && v.length() >= 2)
                || (v.startsWith("'") && v.endsWith("'") && v.length() >= 2)) {
            v = v.substring(1, v.length() - 1);
        }
        return v;
    }

    private static List<String> jsonStringValues(String s) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < s.length()) {
            int q = s.indexOf('"', i);
            if (q < 0) break;
            int end = q + 1;
            while (end < s.length()) {
                char c = s.charAt(end);
                if (c == '\\' && end + 1 < s.length()) { end += 2; continue; }
                if (c == '"') break;
                end++;
            }
            if (end >= s.length()) break;
            out.add(s.substring(q + 1, end));
            i = end + 1;
        }
        return out;
    }

    private void buildClassMapping(ClassPool pool, ObfuscatorContext ctx,
                                   Set<String> referenced, NameGenerator gen,
                                   Map<String, String> mapping) {
        InheritanceAnalyzer inh = ctx.inheritance();
        Set<String> exemptSupers = ctx.exemptions().exemptClassSuperTypes();
        AnnotationScanner ann = ctx.annotations();

        for (ClassNode cn : pool.allClassNodes()) {
            if (referenced.contains(cn.name)) continue;
            if (ctx.exemptions().isClassExempt(cn.name)) continue;
            if (ann != null && ann.isClassExempt(cn.name)) continue;
            if (hasExemptSuperType(cn.name, exemptSupers, inh)) continue;
            // preserve enum / record classes' visible structure: still safe to rename, but skip module-info
            if ((cn.access & Opcodes.ACC_MODULE) != 0) continue;
            String newName = "o/" + gen.next();
            mapping.put(cn.name, newName);
        }
    }

    private boolean hasExemptSuperType(String internal, Set<String> exemptSupers, InheritanceAnalyzer inh) {
        if (inh == null) return false;
        for (String a : inh.ancestors(internal)) {
            if (exemptSupers.contains(a)) return true;
        }
        return false;
    }

    private void buildMethodMapping(ClassPool pool, ObfuscatorContext ctx,
                                    NameGenerator gen, Map<String, String> mapping) {
        InheritanceAnalyzer inh = ctx.inheritance();
        AnnotationScanner ann = ctx.annotations();

        // Union-find over virtual method ownership: key = "owner.name+desc"
        UnionFind uf = new UnionFind();

        // First register every virtual method
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (!isVirtual(mn)) continue;
                uf.add(methodId(cn.name, mn.name, mn.desc));
            }
        }

        // Then union with matching ancestors. When an ancestor is external and we
        // cannot prove the method is new, we still add the external id as an
        // "exempt anchor" so the entire group becomes exempt.
        //
        // Exception: java.lang.Object (and other JDK base types) is an ancestor
        // of every class and is never loaded into our pool/library. Blindly
        // exempting on unknown ancestor there would exempt every virtual method
        // in the program. Instead, for JDK-package ancestors we only exempt
        // methods that match a well-known Object signature.
        Set<String> exemptGroups = new HashSet<>();
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (!isVirtual(mn)) continue;
                String selfId = methodId(cn.name, mn.name, mn.desc);
                for (String ancestor : inh.ancestors(cn.name)) {
                    if (ancestor.equals(cn.name)) continue;
                    ClassNode anc = pool.find(ancestor);
                    if (anc == null) {
                        if (isJdkAncestor(ancestor)) {
                            if (isJdkObjectMethod(mn.name, mn.desc)) {
                                exemptGroups.add(selfId);
                            } else if (jdkAncestorDeclaresMethod(ancestor, mn.name, mn.desc)) {
                                // Ancestor is a JDK class/interface (Runnable,
                                // Comparable, Iterable, Callable, Function, …)
                                // that declares the same virtual method. Keep
                                // the original name so polymorphic dispatch
                                // from the JDK side still finds our impl.
                                exemptGroups.add(selfId);
                            }
                            // else: the JDK ancestor does not declare a
                            // method by that name+desc → safe to rename.
                        } else {
                            // External non-JDK ancestor (platform API we don't
                            // have a library jar for): stay conservative.
                            exemptGroups.add(selfId);
                        }
                        continue;
                    }
                    for (MethodNode am : anc.methods) {
                        if (am.name.equals(mn.name) && am.desc.equals(mn.desc)) {
                            String ancId = methodId(ancestor, mn.name, mn.desc);
                            uf.add(ancId);
                            uf.union(selfId, ancId);
                            if (!pool.classes().containsKey(ancestor)) {
                                exemptGroups.add(selfId);
                            }
                        }
                    }
                }
            }
        }

        // For each group, decide renameable and assign a shared new name
        Map<String, List<String>> groups = uf.groups();
        Map<String, String> groupNewName = new HashMap<>();
        for (Map.Entry<String, List<String>> e : groups.entrySet()) {
            String root = e.getKey();
            List<String> members = e.getValue();
            // exemptGroups is keyed by the raw selfId that was flagged as an
            // exempt anchor. After union-find, that id may or may not be the
            // group root, so we check every member — any one being exempt
            // poisons the whole group.
            boolean exempt = members.stream().anyMatch(exemptGroups::contains)
                    || membersAreExempt(pool, ctx, ann, members);
            if (exempt) continue;
            groupNewName.put(root, gen.next());
        }
        for (Map.Entry<String, List<String>> e : groups.entrySet()) {
            String newName = groupNewName.get(e.getKey());
            if (newName == null) continue;
            for (String id : e.getValue()) {
                MethodKey mk = MethodKey.parse(id);
                if (!pool.classes().containsKey(mk.owner)) continue;
                mapping.put(mk.owner + '.' + mk.name + mk.desc, newName);
            }
        }

        // Static / private methods: rename per-class, not in union-find
        for (ClassNode cn : pool.allClassNodes()) {
            // Class-level exempts apply transitively to members. Otherwise
            // native methods inside an exempted class (e.g. shaded ONNX
            // runtime) get renamed and the native library fails to bind
            // (UnsatisfiedLinkError at JVM-side method lookup).
            if (ctx.exemptions().isClassExempt(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (isVirtual(mn)) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.name.equals("main") && mn.desc.equals("([Ljava/lang/String;)V")) continue;
                if (ctx.exemptions().isMethodExempt(cn.name, mn.name, mn.desc)) continue;
                if (ann != null && ann.isMethodExempt(cn.name, mn.name, mn.desc)) continue;
                mapping.put(cn.name + '.' + mn.name + mn.desc, gen.next());
            }
        }
    }

    private boolean membersAreExempt(ClassPool pool, ObfuscatorContext ctx,
                                     AnnotationScanner ann, List<String> members) {
        for (String id : members) {
            MethodKey mk = MethodKey.parse(id);
            if (!pool.classes().containsKey(mk.owner)) return true;
            // Owner class is itself exempt — protect any virtual method
            // groups that touch it, otherwise siblings of this group on
            // non-exempt classes would force a rename that propagates
            // back into the exempt class.
            if (ctx.exemptions().isClassExempt(mk.owner)) return true;
            if (ctx.exemptions().isMethodExempt(mk.owner, mk.name, mk.desc)) return true;
            if (ann != null && ann.isMethodExempt(mk.owner, mk.name, mk.desc)) return true;
            if (mk.name.startsWith("<")) return true;
        }
        return false;
    }

    private static boolean isVirtual(MethodNode mn) {
        int acc = mn.access;
        if ((acc & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) return false;
        if (mn.name.startsWith("<")) return false;
        return true;
    }

    private static final Set<String> JDK_PACKAGE_PREFIXES = Set.of(
            "java/", "javax/", "jdk/", "sun/", "com/sun/"
    );

    private static final Set<String> OBJECT_VIRTUAL_SIGNATURES = Set.of(
            "equals(Ljava/lang/Object;)Z",
            "hashCode()I",
            "toString()Ljava/lang/String;",
            "clone()Ljava/lang/Object;",
            "finalize()V",
            "getClass()Ljava/lang/Class;",
            "notify()V",
            "notifyAll()V",
            "wait()V",
            "wait(J)V",
            "wait(JI)V"
    );

    private static boolean isJdkAncestor(String internal) {
        for (String p : JDK_PACKAGE_PREFIXES) {
            if (internal.startsWith(p)) return true;
        }
        return false;
    }

    private static boolean isJdkObjectMethod(String name, String desc) {
        return OBJECT_VIRTUAL_SIGNATURES.contains(name + desc);
    }

    // Memoised (internal ancestor name) -> set of "name+desc" pairs declared
    // on that JDK class/interface. Computed via reflection at obfuscator
    // runtime — our obfuscator JAR runs on JDK 17+ so java.lang.Runnable
    // etc. are always resolvable. Includes inherited methods so that a
    // chain like TimerTask → Runnable still protects run()V.
    private static final Map<String, Set<String>> JDK_METHOD_CACHE = new HashMap<>();
    private static final Set<String> JDK_METHOD_MISS_CACHE = new HashSet<>();

    private static boolean jdkAncestorDeclaresMethod(String internalAncestor, String name, String desc) {
        String needle = name + desc;
        Set<String> cached = JDK_METHOD_CACHE.get(internalAncestor);
        if (cached != null) return cached.contains(needle);
        if (JDK_METHOD_MISS_CACHE.contains(internalAncestor)) return false;
        Class<?> cls;
        try {
            cls = Class.forName(internalAncestor.replace('/', '.'), false,
                    Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException | LinkageError t) {
            JDK_METHOD_MISS_CACHE.add(internalAncestor);
            return false;
        }
        Set<String> sigs = new HashSet<>();
        // getMethods() returns all public methods including inherited ones
        // — so java.util.TimerTask via this API reports run()V from Runnable.
        for (java.lang.reflect.Method m : cls.getMethods()) {
            sigs.add(m.getName() + org.objectweb.asm.Type.getMethodDescriptor(m));
        }
        // getDeclaredMethods() adds package/protected methods declared
        // on this class (e.g. AbstractMap.Entry#setValue impl details).
        for (java.lang.reflect.Method m : cls.getDeclaredMethods()) {
            sigs.add(m.getName() + org.objectweb.asm.Type.getMethodDescriptor(m));
        }
        JDK_METHOD_CACHE.put(internalAncestor, sigs);
        return sigs.contains(needle);
    }

    private static String methodId(String owner, String name, String desc) {
        return owner + '.' + name + desc;
    }

    private void buildFieldMapping(ClassPool pool, ObfuscatorContext ctx,
                                   ObfuscatorConfig.NamingStrategy strat,
                                   Map<String, String> mapping) {
        AnnotationScanner ann = ctx.annotations();
        for (ClassNode cn : pool.allClassNodes()) {
            // Class-level exempts apply transitively to fields too — see
            // the equivalent guard in the static/private method loop.
            if (ctx.exemptions().isClassExempt(cn.name)) continue;
            NameGenerator perClass = new NameGenerator(strat);
            for (FieldNode fn : cn.fields) {
                if (ann != null && ann.isFieldExempt(cn.name, fn.name, fn.desc)) continue;
                if (fn.name.equals("serialVersionUID")) continue;
                mapping.put(cn.name + '.' + fn.name, perClass.next());
            }
        }
    }

    private void renameLocals(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            if (mn.localVariables == null) continue;
            int i = 0;
            for (var lv : mn.localVariables) {
                if ("this".equals(lv.name)) continue;
                lv.name = "v" + (i++);
            }
        }
    }

    private void recordMappings(Map<String, String> mapping, ObfuscatorContext ctx) {
        for (Map.Entry<String, String> e : mapping.entrySet()) {
            String k = e.getKey();
            String v = e.getValue();
            int dot = k.indexOf('.');
            if (dot < 0) {
                // class mapping
                ctx.classMapping().put(k, v);
            } else {
                String tail = k.substring(dot + 1);
                if (tail.contains("(")) {
                    ctx.methodMapping().put(k, v);
                } else {
                    ctx.fieldMapping().put(k, v);
                }
            }
        }
    }

    /**
     * Minimal union-find over string keys. Groups methods that belong to the
     * same virtual dispatch chain.
     */
    static final class UnionFind {
        private final Map<String, String> parent = new HashMap<>();

        void add(String id) {
            parent.putIfAbsent(id, id);
        }

        String find(String id) {
            String p = parent.get(id);
            if (p == null) {
                parent.put(id, id);
                return id;
            }
            if (p.equals(id)) return id;
            String root = find(p);
            parent.put(id, root);
            return root;
        }

        void union(String a, String b) {
            add(a);
            add(b);
            String ra = find(a);
            String rb = find(b);
            if (!ra.equals(rb)) parent.put(ra, rb);
        }

        Map<String, List<String>> groups() {
            Map<String, List<String>> out = new LinkedHashMap<>();
            for (String id : parent.keySet()) {
                out.computeIfAbsent(find(id), k -> new ArrayList<>()).add(id);
            }
            return out;
        }
    }

    record MethodKey(String owner, String name, String desc) {
        static MethodKey parse(String id) {
            int dot = id.indexOf('.');
            String owner = id.substring(0, dot);
            String tail = id.substring(dot + 1);
            int paren = tail.indexOf('(');
            String name = tail.substring(0, paren);
            String desc = tail.substring(paren);
            return new MethodKey(owner, name, desc);
        }
    }
}
