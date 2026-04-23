package obfuscator.core;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.nio.file.Path;
import java.util.regex.Pattern;
import java.util.zip.Deflater;

/**
 * Записывает обфусцированные классы и ресурсы в выходной JAR
 */
public class JarWriter {

    public static void write(Path outputPath, ClassPool pool, boolean computeFrames) throws IOException {
        try (JarOutputStream jos = new JarOutputStream(
                outputPath.toFile().toOutputStream())) {
            
            jos.setLevel(Deflater.BEST_COMPRESSION);

            // 1. Записываем обфусцированные ownClasses
            for (Map.Entry<String, ClassNode> entry : pool.getOwnClasses().entrySet()) {
                String className = entry.getKey();
                ClassNode cn = entry.getValue();
                
                byte[] bytes = writeClass(cn, computeFrames);
                String entryName = className + ".class";
                
                JarEntry je = new JarEntry(entryName);
                je.setTime(System.currentTimeMillis());
                jos.putNextEntry(je);
                jos.write(bytes);
                jos.closeEntry();
            }

            // 2. Записываем runtime injected классы (StringDecryptor и т.д.)
            for (Map.Entry<String, ClassNode> entry : pool.getRuntimeInjected().entrySet()) {
                String className = entry.getKey();
                ClassNode cn = entry.getValue();
                
                byte[] bytes = writeClass(cn, computeFrames);
                String entryName = className + ".class";
                
                JarEntry je = new JarEntry(entryName);
                je.setTime(System.currentTimeMillis());
                jos.putNextEntry(je);
                jos.write(bytes);
                jos.closeEntry();
            }

            // 3. Записываем ресурсы (с обновлёнными ссылками на классы)
            for (Map.Entry<String, byte[]> entry : pool.getResources().entrySet()) {
                String resourceName = entry.getKey();
                byte[] content = entry.getValue();
                
                // Пропускаем META-INF/manifests которые будут пересозданы
                if (resourceName.startsWith("META-INF/") && 
                    !resourceName.equals("META-INF/MANIFEST.MF")) {
                    continue;
                }
                
                // Обновляем plugin.yml если есть (main: класс)
                if (resourceName.equals("plugin.yml")) {
                    content = patchPluginYml(content, pool.getMappingTable());
                }
                
                // Обновляем fabric.mod.json
                if (resourceName.equals("fabric.mod.json")) {
                    content = patchFabricModJson(content, pool.getMappingTable());
                }
                
                // Обновляем mods.toml
                if (resourceName.equals("META-INF/mods.toml")) {
                    content = patchModsToml(content, pool.getMappingTable());
                }
                
                JarEntry je = new JarEntry(resourceName);
                je.setTime(System.currentTimeMillis());
                jos.putNextEntry(je);
                jos.write(content);
                jos.closeEntry();
            }

            // 4. Добавляем MANIFEST.MF если его не было
            if (!pool.getResources().containsKey("META-INF/MANIFEST.MF")) {
                JarEntry je = new JarEntry("META-INF/MANIFEST.MF");
                je.setTime(System.currentTimeMillis());
                jos.putNextEntry(je);
                jos.write(("Manifest-Version: 1.0\r\n" +
                          "Created-By: Obfuscator v1.0\r\n" +
                          "\r\n").getBytes());
                jos.closeEntry();
            }
        }
    }

    private static byte[] writeClass(ClassNode cn, boolean computeFrames) {
        int flags = computeFrames ? ClassWriter.COMPUTE_FRAMES : 0;
        ClassWriter cw = new ClassWriter(flags);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private static byte[] patchPluginYml(byte[] content, MappingTable mapping) {
        String yaml = new String(content);
        
        // Находим main: и заменяем имя класса
        // Формат: main: com.example.PluginClass
        for (Map.Entry<String, String> entry : mapping.getClassMappings().entrySet()) {
            String oldName = entry.getKey().replace('/', '.');
            String newName = entry.getValue().replace('/', '.');
            
            // Заменяем main: строку
            yaml = yaml.replaceAll("(?m)^main:\\s*" + Pattern.quote(oldName) + "\\s*$", 
                                   "main: " + newName);
        }
        
        return yaml.getBytes();
    }

    private static byte[] patchFabricModJson(byte[] content, MappingTable mapping) {
        String json = new String(content);
        
        // Обновляем entrypoints
        for (Map.Entry<String, String> entry : mapping.getClassMappings().entrySet()) {
            String oldName = entry.getKey().replace('/', '.');
            String newName = entry.getValue().replace('/', '.');
            json = json.replace(oldName, newName);
        }
        
        return json.getBytes();
    }

    private static byte[] patchModsToml(byte[] content, MappingTable mapping) {
        String toml = new String(content);
        
        // Обновляем modLoader и entry points
        for (Map.Entry<String, String> entry : mapping.getClassMappings().entrySet()) {
            String oldName = entry.getKey().replace('/', '.');
            String newName = entry.getValue().replace('/', '.');
            toml = toml.replace(oldName, newName);
        }
        
        return toml.getBytes();
    }
}
