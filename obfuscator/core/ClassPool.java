package obfuscator.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Central repository for all classes being processed.
 * Holds own classes (to obfuscate), library classes (analysis only),
 * resources, and runtime-injected helper classes.
 */
public class ClassPool {
    private static final Logger LOG = LoggerFactory.getLogger(ClassPool.class);
    
    private final MappingTable mappingTable = new MappingTable();

    // Classes that will be obfuscated
    private final Map<String, ClassNode> ownClasses = new LinkedHashMap<>();
    // Library classes for analysis only (not obfuscated)
    private final Map<String, ClassNode> libClasses = new LinkedHashMap<>();
    // Non-class resources from JARs
    private final Map<String, byte[]> resources = new LinkedHashMap<>();
    // Runtime helper classes injected by obfuscator
    private final Map<String, ClassNode> runtimeInjected = new LinkedHashMap<>();

    public void loadJar(Path jar) throws IOException {
        LOG.info("Loading JAR: {}", jar);
        try (JarFile jf = new JarFile(jar.toFile())) {
            for (JarEntry e : Collections.list(jf.entries())) {
                if (e.isDirectory()) continue;
                byte[] bytes = jf.getInputStream(e).readAllBytes();
                String entryName = e.getName();
                
                if (entryName.endsWith(".class")) {
                    try {
                        ClassNode cn = new ClassNode();
                        ClassReader cr = new ClassReader(bytes);
                        cr.accept(cn, ClassReader.EXPAND_FRAMES);
                        ownClasses.put(cn.name, cn);
                    } catch (Exception ex) {
                        LOG.warn("Failed to parse class {}: {}", entryName, ex.getMessage());
                    }
                } else {
                    // Skip manifest and signature files
                    if (!entryName.startsWith("META-INF/") || 
                        (!entryName.endsWith(".SF") && !entryName.endsWith(".DSA") && !entryName.endsWith(".RSA"))) {
                        resources.put(entryName, bytes);
                    }
                }
            }
        }
        LOG.info("Loaded {} classes and {} resources from {}", ownClasses.size(), resources.size(), jar);
    }

    public void loadLibrary(Path lib) throws IOException {
        LOG.info("Loading library: {}", lib);
        try (JarFile jf = new JarFile(lib.toFile())) {
            for (JarEntry e : Collections.list(jf.entries())) {
                if (e.isDirectory()) continue;
                byte[] bytes = jf.getInputStream(e).readAllBytes();
                String entryName = e.getName();
                
                if (entryName.endsWith(".class")) {
                    try {
                        ClassNode cn = new ClassNode();
                        ClassReader cr = new ClassReader(bytes);
                        cr.accept(cn, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG);
                        libClasses.put(cn.name, cn);
                    } catch (Exception ex) {
                        LOG.debug("Failed to parse library class {}: {}", entryName, ex.getMessage());
                    }
                }
            }
        }
        LOG.info("Loaded {} library classes from {}", libClasses.size(), lib);
    }

    public void injectRuntimeClass(ClassNode cn) {
        runtimeInjected.put(cn.name, cn);
        LOG.debug("Injected runtime class: {}", cn.name);
    }

    public boolean hasClass(String internalName) {
        return ownClasses.containsKey(internalName) || libClasses.containsKey(internalName);
    }

    public ClassNode getClassNode(String internalName) {
        ClassNode cn = ownClasses.get(internalName);
        if (cn == null) cn = libClasses.get(internalName);
        return cn;
    }

    public Map<String, ClassNode> getOwnClasses() {
        return ownClasses;
    }

    public Collection<ClassNode> getOwnClassesCollection() {
        return ownClasses.values();
    }

    public Collection<ClassNode> getLibClasses() {
        return libClasses.values();
    }

    public Map<String, byte[]> getResources() {
        return resources;
    }

    public Collection<ClassNode> getRuntimeInjectedClasses() {
        return runtimeInjected.values();
    }

    public Map<String, ClassNode> getRuntimeInjected() {
        return runtimeInjected;
    }

    public Collection<ClassNode> getAllClasses() {
        List<ClassNode> all = new ArrayList<>();
        all.addAll(ownClasses.values());
        all.addAll(runtimeInjected.values());
        return all;
    }

    public MappingTable getMappingTable() {
        return mappingTable;
    }

    public void addClassMapping(String oldName, String newName) {
        mappingTable.addClassMapping(oldName, newName);
    }

    public void addMethodMapping(String className, String oldName, String desc, String newName) {
        mappingTable.addMethodMapping(className, oldName, desc, newName);
    }

    public void addFieldMapping(String className, String oldName, String newName) {
        mappingTable.addFieldMapping(className, oldName, newName);
    }
}
