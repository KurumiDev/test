package obfuscator.compat;

import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * Совместимость с Forge модом.
 */
public class ForgeCompat implements CompatProfile {
    
    private static final Set<String> EXEMPT_ANNOTATIONS = Set.of(
        "net/minecraftforge/fml/common/Mod",
        "net/minecraftforge/eventbus/api/SubscribeEvent",
        "net/minecraftforge/api/distmarker/Dist",
        "net/minecraftforge/api/distmarker/OnlyIn",
        "net/minecraftforge/registries/ObjectHolder",
        "net/minecraftforge/registries/DeferredRegister",
        "com/google/gson/annotations/SerializedName",
        "com/google/gson/annotations/Expose"
    );
    
    private static final Set<String> EXEMPT_INTERFACES = Set.of(
        "net/minecraftforge/fml/common/IFMLLoadingPlugin",
        "net/minecraftforge/event/IEventBusImpl",
        "java/io/Serializable"
    );
    
    private static final Set<String> EXEMPT_SUPERCLASSES = Set.of(
        "net/minecraft/world/item/Item",
        "net/minecraft/world/level/block/Block",
        "net/minecraft/network/chat/Component",
        "net/minecraft/client/Minecraft"
    );
    
    private static final Set<String> EXEMPT_METHOD_SIGNATURES = Set.of(
        // Mod lifecycle
        "net/minecraftforge/fml/common/Mod#<init>()V",
        
        // Event handlers - все методы с @SubscribeEvent
        "net/minecraftforge/eventbus/api/SubscribeEvent#*",
        
        // Registry methods
        "net/minecraftforge/registries/DeferredRegister#register*"
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
        
        // META-INF/mods.toml - обновляем ссылки на классы
        patchers.put("META-INF/mods.toml", (content, mappings) -> {
            String toml = new String(content);
            for (Map.Entry<String, String> entry : mappings.entrySet()) {
                String oldName = entry.getKey().replace('/', '.');
                String newName = entry.getValue().replace('/', '.');
                toml = toml.replace(oldName, newName);
            }
            return toml.getBytes();
        });
        
        // mods.toml может быть и в корне
        patchers.put("mods.toml", (content, mappings) -> {
            String toml = new String(content);
            for (Map.Entry<String, String> entry : mappings.entrySet()) {
                String oldName = entry.getKey().replace('/', '.');
                String newName = entry.getValue().replace('/', '.');
                toml = toml.replace(oldName, newName);
            }
            return toml.getBytes();
        });
        
        return patchers;
    }
}
