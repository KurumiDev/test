package obfuscator.runtime;

import java.lang.invoke.*;

/**
 * Bootstrap handler для invokedynamic вызовов.
 * Используется с InvokeDynamicTransformer.
 */
public class BootstrapHandler {
    
    /**
     * Bootstrap метод для резолвинга invokedynamic вызовов.
     * 
     * @param lookup MethodHandles.Lookup от JVM
     * @param name имя вызываемого метода (зашифровано)
     * @param type тип метода
     * @param encryptedClass зашифрованное имя класса
     * @param encryptedMethod зашифрованное имя метода
     * @return CallSite с resolved MethodHandle
     */
    public static CallSite resolve(MethodHandles.Lookup lookup, String name, MethodType type,
                                   String encryptedClass, String encryptedMethod) throws Exception {
        // Расшифровываем имена
        int xorKey = computeXorKey(lookup.lookupClass().getName().replace('.', '/'));
        String className = decrypt(encryptedClass, xorKey);
        String methodName = decrypt(encryptedMethod, xorKey);
        
        // Загружаем класс
        Class<?> clazz = Class.forName(className.replace('/', '.'), true, lookup.lookupClass().getClassLoader());
        
        // Находим метод по типу
        Class<?>[] paramTypes = new Class<?>[type.parameterCount()];
        for (int i = 0; i < type.parameterCount(); i++) {
            paramTypes[i] = type.parameterType(i);
        }
        
        java.lang.reflect.Method method = clazz.getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        
        // Создаём MethodHandle
        MethodHandle handle = lookup.unreflect(method);
        
        // Возвращаем ConstantCallSite (кэшируется JVM)
        return new ConstantCallSite(handle);
    }
    
    /**
     * Альтернативный bootstrap для методов без параметров.
     */
    public static CallSite resolveSimple(MethodHandles.Lookup lookup, String name, MethodType type,
                                         String encryptedClass, String encryptedMethod) throws Exception {
        return resolve(lookup, name, type, encryptedClass, encryptedMethod);
    }
    
    /**
     * Bootstrap для статических методов.
     */
    public static CallSite resolveStatic(MethodHandles.Lookup lookup, String name, MethodType type,
                                         String encryptedClass, String encryptedMethod) throws Exception {
        return resolve(lookup, name, type, encryptedClass, encryptedMethod);
    }
    
    /**
     * Вычисляет XOR ключ на основе имени класса.
     */
    private static int computeXorKey(String className) {
        return 0x5A ^ className.hashCode();
    }
    
    /**
     * Расшифровывает строку.
     */
    private static String decrypt(String encrypted, int key) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encrypted.length(); i += 2) {
            int hexVal = Integer.parseInt(encrypted.substring(i, Math.min(i + 2, encrypted.length())), 16);
            byte decrypted = (byte)(hexVal ^ ((key >> ((i / 2) % 4) * 8) & 0xFF));
            sb.append((char)decrypted);
        }
        return sb.toString();
    }
}
