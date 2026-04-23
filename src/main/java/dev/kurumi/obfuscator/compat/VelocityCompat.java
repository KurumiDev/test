package dev.kurumi.obfuscator.compat;

import java.util.Set;

public class VelocityCompat implements CompatProvider {
    @Override
    public String name() {
        return "velocity";
    }

    @Override
    public Set<String> exemptAnnotations() {
        return Set.of(
                "Lcom/velocitypowered/api/plugin/Plugin;",
                "Lcom/velocitypowered/api/plugin/Dependency;",
                "Lcom/velocitypowered/api/event/Subscribe;",
                "Lcom/velocitypowered/api/plugin/annotation/DataDirectory;",
                "Lcom/google/inject/Inject;"
        );
    }

    @Override
    public Set<String> exemptMethodSignatures() {
        return Set.of();
    }

    @Override
    public Set<String> exemptClassSuperTypes() {
        return Set.of();
    }
}
