package obfuscator.compat;

import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * Совместимость с Velocity плагинами.
 */
public class VelocityCompat implements CompatProfile {
    
    private static final Set<String> EXEMPT_ANNOTATIONS = Set.of(
        "com/velocitypowered/api/plugin/Plugin",
        "com/velocitypowered/api/plugin/Injection",
        "com/velocitypowered/api/event/Subscribe",
        "com/google/gson/annotations/SerializedName",
        "com/google/gson/annotations/Expose"
    );
    
    private static final Set<String> EXEMPT_INTERFACES = Set.of(
        "com/velocitypowered/api/event/EventTask",
        "com/velocitypowered/api/command/CommandMeta",
        "java/io/Serializable"
    );
    
    private static final Set<String> EXEMPT_SUPERCLASSES = Set.of(
        "java/lang/Object"
    );
    
    private static final Set<String> EXEMPT_METHOD_SIGNATURES = Set.of(
        // Plugin lifecycle - методы помеченные @Subscribe
        "com/velocitypowered/api/event/Subscribe#*",
        
        // Command execution
        "com/velocitypowered/api/command/CommandManager#register(Lcom/velocitypowered/api/command/Command;)V"
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
        
        // velocity-plugin.json - обновляем main класс
        patchers.put("velocity-plugin.json", (content, mappings) -> {
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
