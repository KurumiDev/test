package com.obfuscator.transformers;

import com.obfuscator.core.ClassPool;

/**
 * Базовый интерфейс для всех трансформеров
 */
public interface Transformer {
    /**
     * Выполнить трансформацию на ClassPool
     */
    void transform(ClassPool classPool);

    /**
     * Получить имя трансформера для логирования
     */
    String getName();
}
