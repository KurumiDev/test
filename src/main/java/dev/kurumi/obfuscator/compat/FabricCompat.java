package dev.kurumi.obfuscator.compat;

import java.util.Set;

public class FabricCompat implements CompatProvider {
    @Override
    public String name() {
        return "fabric";
    }

    @Override
    public Set<String> exemptAnnotations() {
        return Set.of(
                "Lorg/spongepowered/asm/mixin/Mixin;",
                "Lorg/spongepowered/asm/mixin/Shadow;",
                "Lorg/spongepowered/asm/mixin/Overwrite;",
                "Lorg/spongepowered/asm/mixin/Unique;",
                "Lorg/spongepowered/asm/mixin/injection/Inject;",
                "Lorg/spongepowered/asm/mixin/injection/Redirect;",
                "Lorg/spongepowered/asm/mixin/injection/ModifyArg;",
                "Lorg/spongepowered/asm/mixin/injection/ModifyConstant;",
                "Lorg/spongepowered/asm/mixin/injection/ModifyVariable;",
                "Lnet/fabricmc/api/Environment;",
                "Lnet/fabricmc/api/EnvironmentInterface;"
        );
    }

    @Override
    public Set<String> exemptMethodSignatures() {
        return Set.of(
                "onInitialize()V",
                "onInitializeClient()V",
                "onInitializeServer()V"
        );
    }

    @Override
    public Set<String> exemptClassSuperTypes() {
        return Set.of(
                "net/fabricmc/api/ModInitializer",
                "net/fabricmc/api/ClientModInitializer",
                "net/fabricmc/api/DedicatedServerModInitializer"
        );
    }
}
