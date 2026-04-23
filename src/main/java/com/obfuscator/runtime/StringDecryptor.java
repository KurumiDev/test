package com.obfuscator.runtime;

import java.nio.charset.StandardCharsets;

/**
 * Runtime класс для дешифровки строк.
 * Этот класс будет внедрён в обфусцированный JAR.
 */
public class StringDecryptor {
    
    /**
     * LIGHT decrypt - простой XOR
     */
    public static String decryptXOR(byte[] encrypted, int key) {
        byte[] result = new byte[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            result[i] = (byte) (encrypted[i] ^ (key & 0xFF));
        }
        return new String(result, StandardCharsets.UTF_8);
    }
    
    /**
     * STANDARD decrypt - XOR с позиционным ключом
     */
    public static String decryptPositional(byte[] encrypted, int classKey) {
        byte[] result = new byte[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            int key = ((classKey >>> 16) ^ (i * 31)) & 0xFF;
            result[i] = (byte) (encrypted[i] ^ key);
        }
        return new String(result, StandardCharsets.UTF_8);
    }
    
    /**
     * HEAVY decrypt - multiple passes
     */
    public static String decryptHeavy(byte[] encrypted, int classKey) {
        byte[] result = new byte[encrypted.length];
        System.arraycopy(encrypted, 0, result, 0, encrypted.length);
        
        // Pass 1: Reverse XOR с позицией
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (result[i] ^ (i & 0xFF));
        }
        
        // Pass 2: Reverse ROTATE (rotate right 2)
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (((result[i] >>> 2) | (result[i] << 6)) & 0xFF);
        }
        
        // Pass 3: Reverse XOR с ключом класса
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (result[i] ^ ((classKey >>> (i % 4)) & 0xFF));
        }
        
        return new String(result, StandardCharsets.UTF_8);
    }
    
    /**
     * Утилита для преобразования Byte[] в byte[]
     */
    public static byte[] toByteArray(Byte[] boxed) {
        byte[] primitive = new byte[boxed.length];
        for (int i = 0; i < boxed.length; i++) {
            primitive[i] = boxed[i];
        }
        return primitive;
    }
}
