package dev.kurumi.obfuscator.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * In-memory representation of a JAR being processed. Holds every {@link ClassNode}
 * along with all non-class resources. Transformers operate on this pool.
 */
public class ClassPool {

    /** Owned classes (the input JAR, will be transformed and written out). */
    private final Map<String, ClassNode> classNodes = new LinkedHashMap<>();
    /** Non-class files preserved as-is (plugin.yml, META-INF, assets, ...). */
    private final Map<String, byte[]> resources = new LinkedHashMap<>();
    /** Classpath libraries that provide type info but are never mutated or emitted. */
    private final Map<String, ClassNode> libraryNodes = new LinkedHashMap<>();
    /** Manifest bytes (kept separately so we can preserve ordering if needed). */
    private byte[] manifestBytes;

    public void loadJar(Path jarPath) throws IOException {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                byte[] bytes;
                try (InputStream is = jar.getInputStream(entry)) {
                    bytes = is.readAllBytes();
                }
                String name = entry.getName();
                if (name.endsWith(".class") && !name.equals("module-info.class")) {
                    ClassReader cr = new ClassReader(bytes);
                    ClassNode cn = new ClassNode();
                    cr.accept(cn, ClassReader.EXPAND_FRAMES);
                    classNodes.put(cn.name, cn);
                } else if (name.equals("META-INF/MANIFEST.MF")) {
                    manifestBytes = bytes;
                    resources.put(name, bytes);
                } else {
                    resources.put(name, bytes);
                }
            }
        }
    }

    /**
     * Load a library JAR purely for inheritance/analysis context. Classes are
     * stored in {@link #libraryNodes} and never emitted.
     */
    public void loadLibrary(Path libPath) throws IOException {
        try (JarFile jar = new JarFile(libPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) continue;
                try (InputStream is = jar.getInputStream(entry)) {
                    byte[] bytes = is.readAllBytes();
                    ClassReader cr = new ClassReader(bytes);
                    ClassNode cn = new ClassNode();
                    cr.accept(cn, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                    libraryNodes.put(cn.name, cn);
                }
            }
        }
    }

    public Map<String, ClassNode> classes() {
        return classNodes;
    }

    public Collection<ClassNode> allClassNodes() {
        return classNodes.values();
    }

    public boolean containsClass(String internalName) {
        return classNodes.containsKey(internalName);
    }

    public Map<String, byte[]> resources() {
        return resources;
    }

    public Map<String, ClassNode> libraryClasses() {
        return libraryNodes;
    }

    public byte[] manifestBytes() {
        return manifestBytes;
    }

    /** Lookup a class in either the owned pool or libraries. */
    public ClassNode find(String internalName) {
        ClassNode owned = classNodes.get(internalName);
        if (owned != null) return owned;
        return libraryNodes.get(internalName);
    }

    /** Replace class nodes after a remap; invoked by the renamer. */
    public void replaceClasses(Map<String, ClassNode> replacements) {
        classNodes.clear();
        classNodes.putAll(replacements);
    }

    public int size() {
        return classNodes.size();
    }
}
