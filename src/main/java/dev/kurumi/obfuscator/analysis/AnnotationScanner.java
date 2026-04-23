package dev.kurumi.obfuscator.analysis;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.HashSet;
import java.util.Set;

/**
 * Sweeps every annotation in the pool and marks classes/methods/fields whose
 * descriptor appears in {@link ObfuscatorContext#exemptions()}. Results feed
 * the renamer before any name change is committed.
 */
public class AnnotationScanner implements Transformer {

    private final Set<String> exemptClasses = new HashSet<>();
    private final Set<String> exemptMethods = new HashSet<>();
    private final Set<String> exemptFields = new HashSet<>();

    @Override
    public String name() {
        return "annotation-scanner";
    }

    @Override
    public boolean isEnabled(ObfuscatorConfig cfg) {
        return true;
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        exemptClasses.clear();
        exemptMethods.clear();
        exemptFields.clear();
        for (ClassNode cn : pool.allClassNodes()) {
            if (hasExempt(cn.visibleAnnotations, ctx) || hasExempt(cn.invisibleAnnotations, ctx)) {
                exemptClasses.add(cn.name);
            }
            for (MethodNode mn : cn.methods) {
                if (hasExempt(mn.visibleAnnotations, ctx) || hasExempt(mn.invisibleAnnotations, ctx)) {
                    exemptMethods.add(ObfuscatorContext.methodKey(cn.name, mn.name, mn.desc));
                }
            }
            for (FieldNode fn : cn.fields) {
                if (hasExempt(fn.visibleAnnotations, ctx) || hasExempt(fn.invisibleAnnotations, ctx)) {
                    exemptFields.add(ObfuscatorContext.fieldKey(cn.name, fn.name, fn.desc));
                }
            }
        }
        ctx.setAnnotations(this);
    }

    private boolean hasExempt(java.util.List<AnnotationNode> list, ObfuscatorContext ctx) {
        if (list == null) return false;
        for (AnnotationNode a : list) {
            if (ctx.exemptions().isAnnotationExempt(a.desc)) return true;
        }
        return false;
    }

    public boolean isClassExempt(String internal) {
        return exemptClasses.contains(internal);
    }

    public boolean isMethodExempt(String internal, String name, String desc) {
        return exemptMethods.contains(ObfuscatorContext.methodKey(internal, name, desc));
    }

    public boolean isFieldExempt(String internal, String name, String desc) {
        return exemptFields.contains(ObfuscatorContext.fieldKey(internal, name, desc));
    }

    public int exemptClassCount() { return exemptClasses.size(); }
    public int exemptMethodCount() { return exemptMethods.size(); }
    public int exemptFieldCount() { return exemptFields.size(); }
}
