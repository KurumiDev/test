package com.obfuscator.util;

import com.obfuscator.config.ObfuscatorConfig.RenamingStrategy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;

/**
 * NameGenerator — генерирует обфусцированные имена
 * 
 * Стратегии:
 * - ALPHABET   → a, b, c, ..., aa, ab, ...
 * - UNICODE    → \u0001\u0002 (ломает декомпиляторы)
 * - CONFUSE    → Il1IlIl (визуально неразличимые символы)
 * - RANDOM_HEX → a3f2b1c (выглядит как хеш)
 */
public class NameGenerator {
    private final RenamingStrategy strategy;
    private final Random random = new SecureRandom();

    // Счётчик для alphabet стратегии
    private int counter = 0;

    // Символы для confuse стратегии (визуально похожие)
    private static final char[] CONFUSE_CHARS = {
        'I', 'l', '1', '|', '!', 'L', 'j', 'J'
    };

    // Hex символы
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public NameGenerator(RenamingStrategy strategy) {
        this.strategy = strategy;
    }

    /**
     * Сгенерировать имя класса
     */
    public String generateClassName() {
        return switch (strategy) {
            case ALPHABET -> generateAlphabetName();
            case UNICODE -> generateUnicodeName(3);
            case CONFUSE -> generateConfuseName(6);
            case RANDOM_HEX -> generateHexName(8);
        };
    }

    /**
     * Сгенерировать имя метода
     */
    public String generateMethodName() {
        return switch (strategy) {
            case ALPHABET -> generateAlphabetName();
            case UNICODE -> generateUnicodeName(2);
            case CONFUSE -> generateConfuseName(4);
            case RANDOM_HEX -> generateHexName(6);
        };
    }

    /**
     * Сгенерировать имя поля
     */
    public String generateFieldName() {
        return switch (strategy) {
            case ALPHABET -> generateAlphabetName();
            case UNICODE -> generateUnicodeName(2);
            case CONFUSE -> generateConfuseName(4);
            case RANDOM_HEX -> generateHexName(6);
        };
    }

    /**
     * Сгенерировать имя локальной переменной
     */
    public String generateLocalVarName() {
        return switch (strategy) {
            case ALPHABET -> generateAlphabetName();
            case UNICODE -> generateUnicodeName(1);
            case CONFUSE -> generateConfuseName(3);
            case RANDOM_HEX -> generateHexName(4);
        };
    }

    /**
     * Alphabet стратегия: a, b, c, ..., z, aa, ab, ...
     */
    private synchronized String generateAlphabetName() {
        StringBuilder sb = new StringBuilder();
        int n = counter++;
        
        do {
            sb.append((char)('a' + (n % 26)));
            n /= 26;
        } while (n > 0);

        return sb.toString();
    }

    /**
     * Unicode стратегия: генерирует невидимые/специальные символы
     */
    private String generateUnicodeName(int length) {
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < length; i++) {
            // Используем control characters и special unicode
            char c = switch (random.nextInt(4)) {
                case 0 -> (char)(0x0001 + random.nextInt(0x001F)); // Control chars
                case 1 -> (char)(0x0080 + random.nextInt(0x0020)); // Extended control
                case 2 -> (char)(0x200B + random.nextInt(0x0008)); // Zero-width chars
                case 3 -> (char)(0xE000 + random.nextInt(0x1000)); // Private use area
                default -> 'a';
            };
            sb.append(c);
        }

        return sb.toString();
    }

    /**
     * Confuse стратегия: визуально неразличимые символы
     */
    private String generateConfuseName(int length) {
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < length; i++) {
            sb.append(CONFUSE_CHARS[random.nextInt(CONFUSE_CHARS.length)]);
        }

        return sb.toString();
    }

    /**
     * Random Hex стратегия: выглядит как хеш
     */
    private String generateHexName(int length) {
        StringBuilder sb = new StringBuilder();
        
        // Начинаем с буквы чтобы было валидным идентификатором Java
        sb.append(HEX_CHARS[10 + random.nextInt(6)]); // a-f
        
        for (int i = 1; i < length; i++) {
            sb.append(HEX_CHARS[random.nextInt(HEX_CHARS.length)]);
        }

        return sb.toString();
    }

    /**
     * Сгенерировать уникальное имя на основе оригинального (для debug)
     */
    public String generateDeterministicName(String original, String prefix) {
        byte[] bytes = original.getBytes(StandardCharsets.UTF_8);
        int hash = java.util.Arrays.hashCode(bytes);
        
        return switch (strategy) {
            case ALPHABET -> prefix + Math.abs(hash % 10000);
            case UNICODE -> prefix + generateUnicodeName(3);
            case CONFUSE -> prefix + generateConfuseName(5);
            case RANDOM_HEX -> prefix + Integer.toHexString(hash & 0xFFFFFF);
        };
    }

    /**
     * Сбросить счётчик (для новых категорий имён)
     */
    public void reset() {
        counter = 0;
    }
}
