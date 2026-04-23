package com.obfuscator.compat;

import java.util.Set;

/**
 * Совместимость с Paper/Bukkit плагинами
 * Определяет аннотации и методы которые НЕЛЬЗЯ переименовывать
 */
public class PaperPluginCompat {

    private PaperPluginCompat() {}

    /**
     * Аннотации которые защищают элементы от переименования
     * Эти аннотации используются Bukkit reflection
     */
    public static Set<String> getExemptAnnotations() {
        return Set.of(
            "Lorg/bukkit/event/EventHandler;",
            "Lorg/bukkit/plugin/java/annotation/plugin/PluginMeta;",
            "Lorg/bukkit/plugin/java/annotation/plugin/Main;",
            "Lorg/bukkit/plugin/java/annotation/api/FoliaSupported;",
            "Lcom/google/gson/annotations/SerializedName;",
            "Lcom/google/gson/annotations/Expose;",
            "Lorg/jetbrains/annotations/NotNull;",
            "Lorg/jetbrains/annotations/Nullable;"
        );
    }

    /**
     * Методы которые нельзя переименовать — реализуют внешний API
     */
    public static Set<String> getExemptMethodSignatures() {
        return Set.of(
            // JavaPlugin lifecycle
            "onEnable()V",
            "onDisable()V", 
            "onLoad()V",
            
            // Command handling
            "onCommand(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z",
            "onTabComplete(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;",
            "execute(Lorg/bukkit/command/CommandSender;[Ljava/lang/String;)V",
            
            // Event listeners (если класс implements Listener)
            "onClick(Lorg/bukkit/event/player/PlayerInteractEvent;)V",
            "onJoin(Lorg/bukkit/event/player/PlayerJoinEvent;)V",
            "onQuit(Lorg/bukkit/event/player/PlayerQuitEvent;)V",
            "onDamage(Lorg/bukkit/event/entity/EntityDamageEvent;)V",
            "onDeath(Lorg/bukkit/event/entity/PlayerDeathEvent;)V",
            "onChat(Lorg/bukkit/event/player/AsyncPlayerChatEvent;)V",
            
            // Scheduler tasks
            "run()V",
            
            // ConfigurationSerializable
            "serialize()Ljava/util/Map;"
        );
    }

    /**
     * Классы и интерфейсы которые указывают на Paper/Bukkit проект
     */
    public static Set<String> getBukkitIndicators() {
        return Set.of(
            "org/bukkit/plugin/java/JavaPlugin",
            "org/bukkit/event/Listener",
            "org/bukkit/command/CommandExecutor",
            "org/bukkit/command/TabCompleter",
            "org/bukkit/event/Event",
            "org/bukkit/event/Cancellable",
            "net/papermc/paper"
        );
    }

    /**
     * Проверить является ли класс Bukkit Listener-ом
     */
    public static boolean isListenerClass(String className, Set<String> interfaces) {
        return interfaces.contains("org/bukkit/event/Listener") ||
               interfaces.contains("Lorg/bukkit/event/Listener;");
    }

    /**
     * Проверить является ли метод @EventHandler
     */
    public static boolean isEventHandlerMethod(String methodName, String descriptor, 
                                                Set<String> annotations) {
        for (String annotation : annotations) {
            if (annotation.contains("EventHandler")) {
                return true;
            }
        }
        return false;
    }
}
