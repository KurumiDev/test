package obfuscator.compat;

import java.util.Map;

/**
 * Интерфейс для обновления ресурсов после переименования классов.
 */
@FunctionalInterface
public interface ResourcePatcher {
    
    /**
     * Обновляет содержимое ресурса используя mapping таблицу.
     * @param content исходное содержимое
     * @param classMappings маппинг классов: старое имя → новое имя (внутренний формат ASM)
     * @return обновленное содержимое
     */
    byte[] patch(byte[] content, Map<String, String> classMappings);
}
