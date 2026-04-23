package com.obfuscator.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipException;

/**
 * JarWriter — сборка выходного JAR после трансформации
 */
public class JarWriter {
    private static final Logger logger = LoggerFactory.getLogger(JarWriter.class);

    private final ClassPool classPool;

    public JarWriter(ClassPool classPool) {
        this.classPool = classPool;
    }

    /**
     * Записать обфусцированный JAR файл
     * 
     * @param outputPath путь к выходному файлу
     * @throws IOException если ошибка записи
     */
    public void writeJar(Path outputPath) throws IOException {
        // Создаем родительские директории если нужно
        Files.createDirectories(outputPath.getParent());

        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Created-By", "BytecodeObfuscator/1.0.0");

        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(outputPath), manifest)) {
            // Записываем ресурсы (не .class файлы)
            for (var entry : classPool.getResources().entrySet()) {
                writeEntry(jos, entry.getKey(), entry.getValue());
            }

            // Записываем трансформированные классы
            for (var entry : classPool.getClassNodes().entrySet()) {
                String className = entry.getKey();
                ClassNode classNode = entry.getValue();

                byte[] classBytes = writeClass(classNode);
                String entryName = className + ".class";
                
                writeEntry(jos, entryName, classBytes);
            }

            logger.info("JAR written to {}", outputPath.toAbsolutePath());
        }
    }

    /**
     * Алиас для writeJar (для совместимости)
     */
    public void write(Path outputPath) throws IOException {
        writeJar(outputPath);
    }

    /**
     * Записать класс в байты с вычислением frames
     */
    public byte[] writeClass(ClassNode classNode) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        classNode.accept(cw);
        return cw.toByteArray();
    }

    /**
     * Верифицировать что класс корректен перед записью
     * @return список ошибок или пустой список если всё ок
     */
    public java.util.List<String> verifyClass(ClassNode classNode) {
        try {
            byte[] bytes = writeClass(classNode);
            new ClassReader(bytes).accept(new org.objectweb.asm.ClassVisitor(org.objectweb.asm.Opcodes.ASM9) {}, 0);
            return java.util.Collections.emptyList();
        } catch (Exception e) {
            return java.util.Collections.singletonList(e.getMessage());
        }
    }

    private void writeEntry(JarOutputStream jos, String name, byte[] data) throws IOException {
        // Обработка дубликатов и special characters
        JarEntry entry = new JarEntry(name);
        entry.setTime(System.currentTimeMillis());
        
        try {
            jos.putNextEntry(entry);
            jos.write(data);
            jos.closeEntry();
        } catch (ZipException e) {
            if (e.getMessage().contains("duplicate")) {
                logger.warn("Duplicate entry skipped: {}", name);
            } else {
                throw e;
            }
        }
    }

    /**
     * Обновить ClassNode в pool после трансформации
     */
    public void updateClass(String name, ClassNode classNode) {
        // ClassPool не имеет метода set, нужно добавить
    }
}
