package obfuscator.runtime;

import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Runtime decryptor для зашифрованных классов.
 * Используется с ClassEncryptionTransformer.
 */
public class ClassDecryptor {
    
    private static final Map<String, Class<?>> cache = new ConcurrentHashMap<>();
    private static String jarPath;
    
    /**
     * Инициализирует decryptor с путём к JAR файлу.
     */
    public static void init(String path) {
        jarPath = path;
    }
    
    /**
     * Загружает и расшифровывает класс из .encrypted файла.
     */
    public static Class<?> loadClass(ClassLoader loader, String className) throws Exception {
        // Проверяем кэш
        Class<?> cached = cache.get(className);
        if (cached != null) {
            return cached;
        }
        
        // Находим зашифрованный файл в JAR
        String entryName = className.replace('.', '/') + ".encrypted";
        
        try (JarFile jar = new JarFile(jarPath)) {
            JarEntry entry = jar.getJarEntry(entryName);
            if (entry == null) {
                // Пробуем альтернативный формат
                entryName = className.replace('.', '_') + ".encrypted";
                entry = jar.getJarEntry(entryName);
            }
            
            if (entry == null) {
                throw new ClassNotFoundException("Encrypted class not found: " + className);
            }
            
            // Читаем зашифрованные байты
            byte[] encryptedBytes = jar.getInputStream(entry).readAllBytes();
            
            // Расшифровываем
            byte[] decryptedBytes = decrypt(encryptedBytes, className);
            
            // Определяем класс
            Class<?> clazz = defineClass(loader, className, decryptedBytes);
            cache.put(className, clazz);
            
            return clazz;
        }
    }
    
    /**
     * Расшифровывает байты класса.
     * Ключ деривируется из имени класса и machine ID.
     */
    private static byte[] decrypt(byte[] encrypted, String className) {
        // Получаем ключ шифрования
        byte[] key = deriveKey(className);
        
        byte[] decrypted = new byte[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            decrypted[i] = (byte)(encrypted[i] ^ key[i % key.length]);
        }
        
        return decrypted;
    }
    
    /**
     * Деривирует ключ шифрования из имени класса и machine ID.
     */
    private static byte[] deriveKey(String className) {
        // Комбинируем className с machine ID
        String machineId = getMachineId();
        String combined = className + "::" + machineId + "::OBFUSCATOR_KEY_CONSTANT";
        
        // SHA-256 хеш как ключ
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return md.digest(combined.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            // Fallback на простой хеш
            return combined.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }
    
    /**
     * Получает уникальный ID машины для привязки JAR.
     */
    private static String getMachineId() {
        try {
            // Пытаемся получить MAC адрес
            java.net.NetworkInterface ni = java.net.NetworkInterface.getByInetAddress(
                java.net.InetAddress.getLocalHost());
            if (ni != null) {
                byte[] mac = ni.getHardwareAddress();
                if (mac != null) {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : mac) {
                        sb.append(String.format("%02X", b));
                    }
                    return sb.toString();
                }
            }
        } catch (Exception e) {
            // Игнорируем
        }
        
        // Fallback на hostname + user
        return System.getProperty("user.name") + "@" + 
               System.getProperty("java.vm.name");
    }
    
    /**
     * Определяет класс из байтов используя рефлексию.
     */
    private static Class<?> defineClass(ClassLoader loader, String name, byte[] bytes) 
            throws Exception {
        java.lang.reflect.Method defineMethod = ClassLoader.class.getDeclaredMethod(
            "defineClass", String.class, byte[].class, int.class, int.class);
        defineMethod.setAccessible(true);
        
        return (Class<?>) defineMethod.invoke(loader, name, bytes, 0, bytes.length);
    }
}
