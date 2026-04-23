package com.obfuscator.analysis;

import com.obfuscator.core.ClassPool;

/**
 * Интерфейс для фазы анализа
 */
public interface AnalysisPhase {
    /**
     * Выполнить анализ
     */
    void analyze();

    /**
     * Получить имя фазы анализа
     */
    String getName();
}
