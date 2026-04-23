package obfuscator.compat;

import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * Совместимость с Fabric модом.
 */
public class FabricCompat implements CompatProfile {
    
    private static final Set<String> EXEMPT_ANNOTATIONS = Set.of(
        "net/fabricmc/api/Environment",
        "net/fabricmc/api/EnvType",
        "net/fabricmc/fabric/api/client/rendering/v1/ColorProviderRegistry",
        "net/minecraft/class_2960", // Identifier
        "com/google/gson/annotations/SerializedName",
        "com/google/gson/annotations/Expose"
    );
    
    private static final Set<String> EXEMPT_INTERFACES = Set.of(
        "net/fabricmc/api/ModInitializer",
        "net/fabricmc/api/ClientModInitializer",
        "net/fabricmc/api/Entrypoint",
        "net/minecraft/class_4587", // MatrixStack
        "java/io/Serializable"
    );
    
    private static final Set<String> EXEMPT_SUPERCLASSES = Set.of(
        "net/minecraft/class_2248", // Block
        "net/minecraft/class_1792", // Item
        "net/minecraft/class_2561", // TextComponent
        "net/minecraft/class_310"  // MinecraftClient
    );
    
    private static final Set<String> EXEMPT_METHOD_SIGNATURES = Set.of(
        // ModInitializer
        "net/fabricmc/api/ModInitializer#onInitialize()V",
        "net/fabricmc/api/ClientModInitializer#onInitializeClient()V",
        
        // Block/Item lifecycle
        "net/minecraft/class_2248#method_9560(Lnet/minecraft/class_2680;Lnet/minecraft/class_1937;Lnet/minecraft/class_2338;)V",
        
        // Entrypoints - все методы entrypoint
        "net/fabricmc/api/Entrypoint#*"
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
        
        // fabric.mod.json - обновляем entrypoints
        patchers.put("fabric.mod.json", (content, mappings) -> {
            String json = new String(content);
            for (Map.Entry<String, String> entry : mappings.entrySet()) {
                String oldName = entry.getKey().replace('/', '.');
                String newName = entry.getValue().replace('/', '.');
                json = json.replace(oldName, newName);
            }
            return json.getBytes();
        });
        
        return patchers;
    }
}
