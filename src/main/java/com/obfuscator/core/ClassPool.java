package com.obfuscator.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipException;

/**
 * ClassPool загружает ВСЕ классы из JAR в память перед трансформацией.
 * Это критично — трансформеры должны видеть весь граф зависимостей.
 */
public class ClassPool {
    // classNodes: имя класса → ClassNode (ASM Tree API)
    private final Map<String, ClassNode> classNodes = new LinkedHashMap<>();
    // resources: всё что не .class (plugin.yml, sounds.json и т.д.)
    private final Map<String, byte[]> resources = new LinkedHashMap<>();
    // libraryClasses: классы из библиотек для анализа иерархии
    private final Map<String, ClassNode> libraryClasses = new LinkedHashMap<>();

    /**
     * Загрузить основной JAR файл для обфускации
     */
    public void loadJar(Path jarPath) throws IOException {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                
                if (entry.isDirectory()) {
                    continue;
                }

                byte[] bytes = readAllBytes(jar, entry);

                if (entry.getName().endsWith(".class")) {
                    ClassReader cr = new ClassReader(bytes);
                    ClassNode cn = new ClassNode();
                    // EXPAND_FRAMES критично для flow трансформеров
                    cr.accept(cn, ClassReader.EXPAND_FRAMES);
                    classNodes.put(cn.name, cn);
                } else {
                    // Не добавляем META-INF/MANIFEST.MF - создадим новый
                    if (!entry.getName().startsWith("META-INF/MANIFEST.MF")) {
                        resources.put(entry.getName(), bytes);
                    }
                }
            }
        }
    }

    /**
     * Загрузить внешние library JARs для анализа иерархии (не обфусцировать)
     */
    public void loadLibrary(Path libPath) throws IOException {
        try (JarFile jar = new JarFile(libPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }

                byte[] bytes = readAllBytes(jar, entry);
                ClassReader cr = new ClassReader(bytes);
                ClassNode cn = new ClassNode();
                cr.accept(cn, ClassReader.EXPAND_FRAMES);
                libraryClasses.put(cn.name, cn);
            }
        }
    }

    /**
     * Загрузить несколько библиотек из директории
     */
    public void loadLibrariesFromDirectory(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        Files.list(dir)
            .filter(p -> p.toString().endsWith(".jar"))
            .forEach(p -> {
                try {
                    loadLibrary(p);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to load library: " + p, e);
                }
            });
    }

    private byte[] readAllBytes(JarFile jar, JarEntry entry) throws IOException {
        try (var is = jar.getInputStream(entry)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            is.transferTo(baos);
            return baos.toByteArray();
        }
    }

    public Map<String, ClassNode> getClassNodes() {
        return Collections.unmodifiableMap(classNodes);
    }

    public Map<String, byte[]> getResources() {
        return Collections.unmodifiableMap(resources);
    }

    /**
     * Получить ClassNode по имени, включая библиотеки
     */
    public ClassNode getClassNode(String name) {
        ClassNode node = classNodes.get(name);
        if (node == null) {
            node = libraryClasses.get(name);
        }
        return node;
    }

    /**
     * Проверить является ли класс частью основного JAR (не библиотека)
     */
    public boolean isMainClass(String name) {
        return classNodes.containsKey(name);
    }

    /**
     * Получить все классы которые можно обфусцировать
     */
    public Collection<ClassNode> getObfuscatableClasses() {
        return classNodes.values();
    }

    public int getClassCount() {
        return classNodes.size();
    }

    public int getLibraryClassCount() {
        return libraryClasses.size();
    }

    public int getResourceCount() {
        return resources.size();
    }
}
