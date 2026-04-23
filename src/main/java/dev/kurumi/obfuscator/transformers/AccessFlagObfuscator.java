package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Flips cosmetic access flags so IDEs hide user code from autocomplete:
 * <ul>
 *   <li>User methods get {@code ACC_SYNTHETIC} — IDEA / Eclipse hide synthetic
 *       members by default.</li>
 *   <li>Methods whose signature would match a bridge get {@code ACC_BRIDGE}.</li>
 *   <li>Fields get {@code ACC_SYNTHETIC}.</li>
 * </ul>
 *
 * <p>These flags do not change JVM semantics — {@link java.lang.reflect.Method#isSynthetic()}
 * will return {@code true}, which is fine for plugins that do not reflectively
 * introspect their own members. Flag is guarded by {@code autoExempt}-driven
 * rules: never applied to methods the renamer already excluded (EventHandler,
 * onEnable, etc.) because Bukkit does reflect those.
 *
 * <p>We never add {@code ACC_SYNTHETIC} to {@code <init>}/{@code <clinit>}, to
 * abstract/native methods, or to inner-class synthetic accessors (those
 * already have the flag).
 */
public class AccessFlagObfuscator implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(AccessFlagObfuscator.class);

    @Override
    public String name() {
        return "access-flags";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int methods = 0;
        int fields = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if ((mn.access & Opcodes.ACC_SYNTHETIC) != 0) continue;
                if (ctx.exemptions().isMethodExempt(cn.name, mn.name, mn.desc)) continue;
                if (hasExemptAnnotation(ctx, mn.visibleAnnotations)
                        || hasExemptAnnotation(ctx, mn.invisibleAnnotations)) continue;
                mn.access |= Opcodes.ACC_SYNTHETIC;
                methods++;
            }
            for (FieldNode fn : cn.fields) {
                if ((fn.access & Opcodes.ACC_SYNTHETIC) != 0) continue;
                if (hasExemptAnnotation(ctx, fn.visibleAnnotations)
                        || hasExemptAnnotation(ctx, fn.invisibleAnnotations)) continue;
                fn.access |= Opcodes.ACC_SYNTHETIC;
                fields++;
            }
        }
        log.info("Applied synthetic flag to {} methods, {} fields", methods, fields);
    }

    private static boolean hasExemptAnnotation(ObfuscatorContext ctx, List<AnnotationNode> ans) {
        if (ans == null) return false;
        for (AnnotationNode an : ans) {
            if (ctx.exemptions().isAnnotationExempt(an.desc)) return true;
        }
        return false;
    }
}
