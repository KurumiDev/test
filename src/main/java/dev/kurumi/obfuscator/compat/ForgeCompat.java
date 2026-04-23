package dev.kurumi.obfuscator.compat;

import java.util.Set;

public class ForgeCompat implements CompatProvider {
    @Override
    public String name() {
        return "forge";
    }

    @Override
    public Set<String> exemptAnnotations() {
        return Set.of(
                "Lnet/minecraftforge/fml/common/Mod;",
                "Lnet/minecraftforge/fml/common/Mod$EventBusSubscriber;",
                "Lnet/minecraftforge/eventbus/api/SubscribeEvent;",
                "Lnet/minecraftforge/fml/event/lifecycle/FMLCommonSetupEvent;",
                "Lnet/minecraftforge/registries/ObjectHolder;",
                "Lnet/minecraftforge/registries/RegisterEvent;"
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
