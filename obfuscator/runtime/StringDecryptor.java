package obfuscator.runtime;

/**
 * Runtime decryptor для строк.
 * Этот класс ВШИВАЕТСЯ в обфусцированный JAR и используется во время выполнения.
 * 
 * Методы этого класса инлайнятся в каждый класс где есть зашифрованные строки.
 */
public class StringDecryptor {
    
    /**
     * Расшифровывает строку используя XOR ключ.
     * Используется для STANDARD уровня шифрования.
     */
    public static String decrypt(String encrypted, int key) {
        if (encrypted == null) return null;
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encrypted.length(); i += 2) {
            int hexVal = Integer.parseInt(encrypted.substring(i, Math.min(i + 2, encrypted.length())), 16);
            byte decrypted = (byte)(hexVal ^ ((key >> ((i / 2) % 4) * 8) & 0xFF));
            sb.append((char)decrypted);
        }
        return sb.toString();
    }
    
    /**
     * Расшифровывает строку используя ключ на основе className, methodName и instructionIndex.
     * Используется для HEAVY уровня шифрования.
     */
    public static String decryptHeavy(String encrypted, String className, String methodName, int index) {
        if (encrypted == null) return null;
        
        // Вычисляем ключ на основе контекста
        int key = (className.hashCode() * 31 + methodName.hashCode()) ^ index;
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encrypted.length(); i += 2) {
            int hexVal = Integer.parseInt(encrypted.substring(i, Math.min(i + 2, encrypted.length())), 16);
            byte decrypted = (byte)(hexVal ^ ((key >> ((i / 2) % 4) * 8) & 0xFF));
            sb.append((char)decrypted);
        }
        return sb.toString();
    }
    
    /**
     * SUPER_HEAVY версия - проверяет стек вызовов перед расшифровкой.
     * Если вызвано не из "правильного" метода - возвращает мусор.
     */
    public static String decryptSuperHeavy(String encrypted, String expectedClass, String expectedMethod, int index) {
        // Проверяем стек вызовов
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        
        // stack[0] = getStackTrace
        // stack[1] = decryptSuperHeavy
        // stack[2] = вызывающий метод
        if (stack.length < 3) {
            return "!!!INVALID_CALL!!!";
        }
        
        StackTraceElement caller = stack[2];
        String callerClass = caller.getClassName().replace('.', '/');
        String callerMethod = caller.getMethodName();
        
        // Проверяем что вызов из ожидаемого места
        if (!callerClass.equals(expectedClass) || !callerMethod.equals(expectedMethod)) {
            // Возвращаем мусор чтобы запутать анализ
            return generateFakeString(encrypted.length() / 2);
        }
        
        // Расшифровываем как обычно
        return decryptHeavy(encrypted, expectedClass, expectedMethod, index);
    }
    
    /**
     * Генерирует фейковую строку для дезинформации злоумышленника.
     */
    private static String generateFakeString(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append((char)('!' + (i * 7) % 95)); // Печатаемые ASCII символы
        }
        return sb.toString();
    }
    
    /**
     * Decryptor для switch-dispatch версии.
     * Принимает ID строки и расшифровывает соответствующую строку из массива.
     */
    public static String decryptSwitch(String[] encryptedArray, int id, String className, String methodName) {
        if (id < 0 || id >= encryptedArray.length) {
            return "!!!INVALID_ID!!!";
        }
        
        // Ключ зависит от позиции в массиве
        return decryptHeavy(encryptedArray[id], className, methodName, id);
    }
}
