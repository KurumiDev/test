package obfuscator.compat;

import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * Совместимость с Paper/Bukkit/Spigot плагинами.
 */
public class PaperCompat implements CompatProfile {
    
    private static final Set<String> EXEMPT_ANNOTATIONS = Set.of(
        "org/bukkit/event/EventHandler",
        "org/bukkit/command/CommandExecutor",
        "org/bukkit/command/TabCompleter",
        "org/bukkit/configuration/serialization/SerializableAs",
        "com/google/gson/annotations/SerializedName",
        "com/google/gson/annotations/Expose",
        "org/jetbrains/annotations/NotNull",
        "org/jetbrains/annotations/Nullable"
    );
    
    private static final Set<String> EXEMPT_INTERFACES = Set.of(
        "org/bukkit/event/Listener",
        "org/bukkit/command/CommandExecutor",
        "org/bukkit/command/TabCompleter",
        "org/bukkit/plugin/Plugin",
        "org/bukkit/configuration/serialization/ConfigurationSerializable",
        "java/io/Serializable"
    );
    
    private static final Set<String> EXEMPT_SUPERCLASSES = Set.of(
        "org/bukkit/plugin/java/JavaPlugin",
        "org/bukkit/scheduler/BukkitRunnable",
        "org/bukkit/command/Command",
        "org/bukkit/command/PluginCommand"
    );
    
    private static final Set<String> EXEMPT_METHOD_SIGNATURES = Set.of(
        // JavaPlugin lifecycle
        "org/bukkit/plugin/java/JavaPlugin#onEnable()V",
        "org/bukkit/plugin/java/JavaPlugin#onDisable()V",
        "org/bukkit/plugin/java/JavaPlugin#onLoad()V",
        
        // CommandExecutor
        "org/bukkit/command/CommandExecutor#onCommand(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z",
        "org/bukkit/command/TabCompleter#onTabComplete(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;",
        
        // BukkitRunnable
        "org/bukkit/scheduler/BukkitRunnable#run()V",
        
        // Listener - все публичные методы (wildcard обрабатывается в ExemptionResolver)
        "org/bukkit/event/Listener#*"
    );
    
    @Override
    public Set<String> getExemptAnnotations() {
        return EXEMPT_ANNOTATIONS;
    }
    
    @Override
    public Set<String> getExemptInterfaces() {
        return EXEMPT_INTERFACES;
    }
    
    @Override
    public Set<String> getExemptSuperclasses() {
        return EXEMPT_SUPERCLASSES;
    }
    
    @Override
    public Set<String> getExemptMethodSignatures() {
        return EXEMPT_METHOD_SIGNATURES;
    }
    
    @Override
    public Map<String, ResourcePatcher> getResourcePatchers() {
        Map<String, ResourcePatcher> patchers = new HashMap<>();
        
        // plugin.yml - обновляем main: класс
        patchers.put("plugin.yml", (content, mappings) -> {
            String yaml = new String(content);
            for (Map.Entry<String, String> entry : mappings.entrySet()) {
                String oldName = entry.getKey().replace('/', '.');
                String newName = entry.getValue().replace('/', '.');
                
                // Заменяем main: строку
                yaml = yaml.replaceAll("(?m)^main:\\s*" + Pattern.quote(oldName) + "\\s*$", 
                                       "main: " + newName);
                
                // Заменяем другие ссылки на классы в plugin.yml (depend, softdepend, loadbefore)
                yaml = yaml.replace(oldName, newName);
            }
            return yaml.getBytes();
        });
        
        return patchers;
    }
    
    @Override
    public Set<String> getExemptPackages() {
        return Set.of();
    }
    
    @Override
    public Set<String> getUnencryptableClasses() {
        return Set.of(
            // Сериализуемые классы нельзя шифровать
            "java/io/Serializable"
        );
    }
}
