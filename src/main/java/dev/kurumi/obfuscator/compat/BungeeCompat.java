package dev.kurumi.obfuscator.compat;

import java.util.Set;

public class BungeeCompat implements CompatProvider {
    @Override
    public String name() {
        return "bungee";
    }

    @Override
    public Set<String> exemptAnnotations() {
        return Set.of(
                "Lnet/md_5/bungee/event/EventHandler;",
                "Lcom/google/gson/annotations/SerializedName;"
        );
    }

    @Override
    public Set<String> exemptMethodSignatures() {
        return Set.of(
                "onEnable()V",
                "onDisable()V",
                "onLoad()V",
                "execute(Lnet/md_5/bungee/api/CommandSender;[Ljava/lang/String;)V",
                "onTabComplete(Lnet/md_5/bungee/api/CommandSender;[Ljava/lang/String;)Ljava/lang/Iterable;"
        );
    }

    @Override
    public Set<String> exemptClassSuperTypes() {
        return Set.of(
                "net/md_5/bungee/api/plugin/Plugin",
                "net/md_5/bungee/api/plugin/Listener",
                "net/md_5/bungee/api/plugin/Command",
                "net/md_5/bungee/api/plugin/TabExecutor"
        );
    }
}
