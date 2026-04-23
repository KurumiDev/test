package dev.kurumi.obfuscator.core;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * Writes a {@link ClassPool} out to a JAR file on disk. Applies
 * {@link ClassWriter#COMPUTE_FRAMES} + {@link ClassWriter#COMPUTE_MAXS} so that
 * transformers never need to track stack frames manually.
 */
public class JarWriter {

    private final ClassPool pool;
    private final FrameComputingClassWriterFactory writerFactory;

    public JarWriter(ClassPool pool) {
        this.pool = pool;
        this.writerFactory = new FrameComputingClassWriterFactory(pool);
    }

    public void write(Path outputPath) throws IOException {
        Path parent = outputPath.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);

        try (OutputStream os = Files.newOutputStream(outputPath);
             BufferedOutputStream bos = new BufferedOutputStream(os);
             JarOutputStream jos = new JarOutputStream(bos)) {

            for (Map.Entry<String, byte[]> res : pool.resources().entrySet()) {
                JarEntry e = new JarEntry(res.getKey());
                jos.putNextEntry(e);
                jos.write(res.getValue());
                jos.closeEntry();
            }

            for (ClassNode cn : pool.allClassNodes()) {
                byte[] bytes = writerFactory.toBytes(cn);
                JarEntry e = new JarEntry(cn.name + ".class");
                jos.putNextEntry(e);
                jos.write(bytes);
                jos.closeEntry();
            }
        }
    }
}
