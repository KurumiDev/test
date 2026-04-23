package dev.kurumi.obfuscator.compat;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import org.objectweb.asm.tree.ClassNode;

import java.util.Map;

/**
 * Heuristic detection of the platform type from the contents of a JAR. Looks at
 * resource descriptors (plugin.yml, fabric.mod.json, mods.toml, velocity-plugin.json)
 * and then falls back to scanning class imports.
 */
public final class TargetDetector {

    private TargetDetector() {}

    public static ObfuscatorConfig.Target detect(ClassPool pool) {
        Map<String, byte[]> res = pool.resources();
        if (res.containsKey("fabric.mod.json")) return ObfuscatorConfig.Target.FABRIC;
        if (res.containsKey("META-INF/mods.toml")
                || res.containsKey("META-INF/neoforge.mods.toml")) return ObfuscatorConfig.Target.FORGE;
        if (res.containsKey("velocity-plugin.json")) return ObfuscatorConfig.Target.VELOCITY;
        if (res.containsKey("bungee.yml")) return ObfuscatorConfig.Target.BUNGEE;
        if (res.containsKey("plugin.yml") || res.containsKey("paper-plugin.yml")) {
            return ObfuscatorConfig.Target.PAPER;
        }

        int bukkitRefs = 0;
        int fabricRefs = 0;
        int forgeRefs = 0;
        int bungeeRefs = 0;
        int velocityRefs = 0;

        for (ClassNode cn : pool.allClassNodes()) {
            if (cn.superName != null) {
                if (cn.superName.startsWith("org/bukkit/")) bukkitRefs++;
                if (cn.superName.startsWith("net/fabricmc/")) fabricRefs++;
                if (cn.superName.startsWith("net/minecraftforge/")) forgeRefs++;
                if (cn.superName.startsWith("net/md_5/bungee/")) bungeeRefs++;
                if (cn.superName.startsWith("com/velocitypowered/")) velocityRefs++;
            }
            if (cn.interfaces != null) {
                for (String iface : cn.interfaces) {
                    if (iface.startsWith("org/bukkit/")) bukkitRefs++;
                    if (iface.startsWith("net/fabricmc/")) fabricRefs++;
                    if (iface.startsWith("net/minecraftforge/")) forgeRefs++;
                    if (iface.startsWith("net/md_5/bungee/")) bungeeRefs++;
                    if (iface.startsWith("com/velocitypowered/")) velocityRefs++;
                }
            }
        }

        int max = Math.max(Math.max(Math.max(bukkitRefs, fabricRefs), Math.max(forgeRefs, bungeeRefs)), velocityRefs);
        if (max == 0) return ObfuscatorConfig.Target.PLAIN;
        if (max == bukkitRefs) return ObfuscatorConfig.Target.PAPER;
        if (max == fabricRefs) return ObfuscatorConfig.Target.FABRIC;
        if (max == forgeRefs) return ObfuscatorConfig.Target.FORGE;
        if (max == bungeeRefs) return ObfuscatorConfig.Target.BUNGEE;
        return ObfuscatorConfig.Target.VELOCITY;
    }
}
