package dev.kurumi.obfuscator.compat;

import java.util.Set;

/** Exemptions for Bukkit / Spigot / Paper plugins. */
public class PaperPluginCompat implements CompatProvider {

    @Override
    public String name() {
        return "paper";
    }

    @Override
    public Set<String> exemptAnnotations() {
        return Set.of(
                "Lorg/bukkit/event/EventHandler;",
                "Lorg/bukkit/plugin/java/annotation/command/Command;",
                "Lorg/bukkit/plugin/java/annotation/command/Commands;",
                "Lorg/bukkit/plugin/java/annotation/plugin/Plugin;",
                "Lorg/bukkit/plugin/java/annotation/plugin/ApiVersion;",
                "Lorg/bukkit/plugin/java/annotation/plugin/LogPrefix;",
                "Lorg/bukkit/plugin/java/annotation/plugin/author/Author;",
                "Lorg/bukkit/plugin/java/annotation/plugin/author/Authors;",
                "Lorg/bukkit/plugin/java/annotation/dependency/Dependency;",
                "Lorg/bukkit/plugin/java/annotation/dependency/SoftDependency;",
                "Lcom/google/gson/annotations/SerializedName;",
                "Lcom/google/gson/annotations/Expose;"
        );
    }

    @Override
    public Set<String> exemptMethodSignatures() {
        return Set.of(
                "onEnable()V",
                "onDisable()V",
                "onLoad()V",
                "onCommand(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Z",
                "onTabComplete(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;",
                "execute(Lorg/bukkit/command/CommandSender;Ljava/lang/String;[Ljava/lang/String;)Z",
                "tabComplete(Lorg/bukkit/command/CommandSender;Ljava/lang/String;[Ljava/lang/String;)Ljava/util/List;"
        );
    }

    @Override
    public Set<String> exemptClassSuperTypes() {
        return Set.of(
                "org/bukkit/plugin/java/JavaPlugin",
                "org/bukkit/event/Listener",
                "org/bukkit/command/CommandExecutor",
                "org/bukkit/command/TabCompleter",
                "org/bukkit/command/TabExecutor",
                "org/bukkit/configuration/serialization/ConfigurationSerializable",
                "org/bukkit/inventory/InventoryHolder"
        );
    }
}
