package compat;

import java.util.Set;

/**
 * Paper/Bukkit/Spigot compatibility profile.
 */
public class PaperCompat {
    
    private static final Set<String> EXEMPT_ANNOTATIONS = Set.of(
        "org/bukkit/event/EventHandler",
        "org/bukkit/command/CommandExecutor",
        "org/bukkit/command/TabCompleter",
        "org/jetbrains/annotations/NotNull",
        "org/jetbrains/annotations/Nullable"
    );

    private static final Set<String> EXEMPT_INTERFACES = Set.of(
        "org/bukkit/event/Listener",
        "org/bukkit/command/CommandExecutor",
        "org/bukkit/command/TabCompleter",
        "java/io/Serializable"
    );

    private static final Set<String> EXEMPT_SUPERCLASSES = Set.of(
        "org/bukkit/plugin/java/JavaPlugin",
        "org/bukkit/plugin/java/JavaPluginLoader"
    );

    private static final Set<String> EXEMPT_METHODS = Set.of(
        "org/bukkit/plugin/java/JavaPlugin.onEnable()V",
        "org/bukkit/plugin/java/JavaPlugin.onDisable()V",
        "org/bukkit/plugin/java/JavaPlugin.onLoad()V",
        "org/bukkit/command/CommandExecutor.onCommand(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z",
        "org/bukkit/command/TabCompleter.onTabComplete(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;"
    );

    public Set<String> getExemptAnnotations() { return EXEMPT_ANNOTATIONS; }
    public Set<String> getExemptInterfaces() { return EXEMPT_INTERFACES; }
    public Set<String> getExemptSuperclasses() { return EXEMPT_SUPERCLASSES; }
    public Set<String> getExemptMethodSignatures() { return EXEMPT_METHODS; }
    public String getMainClassResource() { return "plugin.yml"; }
}
