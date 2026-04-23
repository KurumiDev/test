package obfuscator.compat;

import java.util.Set;
import java.util.Map;

/**
 * Интерфейс совместимости с различными платформами.
 * Определяет exempt аннотации, интерфейсы, суперклассы и методы.
 */
public interface CompatProfile {
    
    /**
     * Аннотации — методы/классы с этими аннотациями нельзя переименовывать
     */
    Set<String> getExemptAnnotations();
    
    /**
     * Интерфейсы — реализации этих интерфейсов нельзя переименовывать (публичные методы)
     */
    Set<String> getExemptInterfaces();
    
    /**
     * Суперклассы — наследники этих классов имеют ограничения на переименование
     */
    Set<String> getExemptSuperclasses();
    
    /**
     * Конкретные сигнатуры методов которые нельзя трогать
     * Формат: "className#methodName(Ljava/lang/String;)V"
     */
    Set<String> getExemptMethodSignatures();
    
    /**
     * Файлы ресурсов которые нужно обновить после renaming
     * Ключ: имя ресурса, Значение: патчер
     */
    Map<String, ResourcePatcher> getResourcePatchers();
    
    /**
     * Пакеты которые следует исключить из агрессивной обфускации
     */
    default Set<String> getExemptPackages() {
        return Set.of();
    }
    
    /**
     * Классы которые никогда не должны быть зашифрованы
     */
    default Set<String> getUnencryptableClasses() {
        return Set.of();
    }
}
