package obfuscator.compat;

import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * Совместимость с BungeeCord плагинами.
 */
public class BungeeCompat implements CompatProfile {
    
    private static final Set<String> EXEMPT_ANNOTATIONS = Set.of(
        "net/md_5/bungee/event/EventHandler",
        "com/google/gson/annotations/SerializedName",
        "com/google/gson/annotations/Expose"
    );
    
    private static final Set<String> EXEMPT_INTERFACES = Set.of(
        "net/md_5/bungee/api/plugin/Listener",
        "net/md_5/bungee/api/command/CommandExecutor",
        "net/md_5/bungee/api/command/TabCompleter",
        "java/io/Serializable"
    );
    
    private static final Set<String> EXEMPT_SUPERCLASSES = Set.of(
        "net/md_5/bungee/api/plugin/Plugin",
        "net/md_5/bungee/api/connection/ConnectionHandler"
    );
    
    private static final Set<String> EXEMPT_METHOD_SIGNATURES = Set.of(
        // Plugin lifecycle
        "net/md_5/bungee/api/plugin/Plugin#onEnable()V",
        "net/md_5/bungee/api/plugin/Plugin#onDisable()V",
        
        // CommandExecutor
        "net/md_5/bungee/api/command/CommandExecutor#execute(Lnet/md_5/bungee/api/command/CommandSender;[Ljava/lang/String;)V",
        
        // Listener
        "net/md_5/bungee/api/plugin/Listener#*"
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
        
        // bungee.yml - обновляем main: класс
        patchers.put("bungee.yml", (content, mappings) -> {
            String yaml = new String(content);
            for (Map.Entry<String, String> entry : mappings.entrySet()) {
                String oldName = entry.getKey().replace('/', '.');
                String newName = entry.getValue().replace('/', '.');
                
                yaml = yaml.replaceAll("(?m)^main:\\s*" + Pattern.quote(oldName) + "\\s*$", 
                                       "main: " + newName);
                yaml = yaml.replace(oldName, newName);
            }
            return yaml.getBytes();
        });
        
        return patchers;
    }
}
