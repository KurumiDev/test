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
        // JavaPlugin subclasses are pinned by plugin.yml's `main:` (handled in the
        // resource scanner). Listener / CommandExecutor / TabCompleter do NOT need
        // class-level exemption — Bukkit finds them at runtime via the plugin
        // instance (registerEvents / getCommand().setExecutor()); only the
        // @EventHandler-annotated methods and the well-known method signatures
        // (onCommand, onTabComplete…) must keep their names, which are already
        // covered by exemptAnnotations() and exemptMethodSignatures().
        //
        // ConfigurationSerializable is genuinely reflection-pinned (Bukkit loads
        // it by class name via deserialize()). InventoryHolder is a marker
        // interface and safe to rename, but kept here as a conservative default.
        return Set.of(
                // Pinned as the plugin entry point (redundantly — the resource
                // scanner also reads plugin.yml's `main:` — but kept as a
                // defence-in-depth against plugin.yml-less inputs).
                "org/bukkit/plugin/java/JavaPlugin",
                "org/bukkit/configuration/serialization/ConfigurationSerializable"
        );
    }
}
