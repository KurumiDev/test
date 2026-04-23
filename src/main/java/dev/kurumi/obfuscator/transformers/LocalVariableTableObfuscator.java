package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Rewrites {@code LocalVariableTable} entries with meaningless / confusing
 * names — Java reserved keywords, obfuscator-ish single glyphs, or
 * zero-width-joined strings — so IDEs and decompilers display nonsensical
 * identifiers in their decompiled source.
 *
 * <p>Unlike {@link LocalVariableTransformer} (which strips the table
 * entirely), this keeps the attribute present so the class still appears
 * "debuggable" at a glance, but every local name is a honeypot:
 * {@code int class = ...}, {@code String null = ...}. A decompiler that
 * preserves local names (CFR, Fernflower) emits code that won't compile and
 * is misleading to read.
 *
 * <p>Runs <b>after</b> {@link LocalVariableTransformer}: if both are
 * enabled, LocalVariableTransformer strips the original table first, then
 * this pass injects a synthetic one.
 */
public class LocalVariableTableObfuscator implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(LocalVariableTableObfuscator.class);

    // A mix of Java reserved keywords (uncompilable if preserved as
    // identifiers), punctuation, single-char confusables, and zero-width
    // codepoints that break copy-paste.
    private static final String[] CONFUSING_NAMES = {
            "class", "null", "int", "true", "false", "this", "new",
            "return", "if", "else", "while", "for", "void",
            "\u03bf", // Greek small omicron — looks like 'o'
            "\u0131", // dotless i
            "\u0261", // script g
            "I", "l", "1",
            "\u200b\u200b", // two zero-width spaces
            "\u2060",       // word joiner
            "_", "__", "___"
    };

    @Override
    public String name() {
        return "local-variable-table";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        int methodsTouched = 0;
        int totalEntries = 0;
        for (ClassNode cn : pool.allClassNodes()) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                int entries = rewriteMethod(cn, mn);
                if (entries > 0) {
                    methodsTouched++;
                    totalEntries += entries;
                }
            }
        }
        if (totalEntries > 0) {
            log.info("Injected {} confusing local-var entries across {} methods",
                    totalEntries, methodsTouched);
        } else {
            log.info("No methods eligible for local-var-table obfuscation");
        }
    }

    /**
     * Replaces the method's existing {@code LocalVariableTable} (if any)
     * with a fresh table where every slot across the method's whole lifetime
     * is labelled with a confusing name drawn deterministically from
     * {@link #CONFUSING_NAMES} keyed by method signature.
     *
     * <p>Chooses {@code Object} as the advertised type for all non-primitive
     * slots to avoid having to track real types (primitives stay as their
     * actual ASM sort to keep the table self-consistent with any descriptor
     * parsing the decompiler does).
     */
    private int rewriteMethod(ClassNode cn, MethodNode mn) {
        // Find first and last actual label in the method to bound the synthetic
        // LVT entries. If no labels exist, skip — we can't point to anything.
        LabelNode first = null;
        LabelNode last = null;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode lbl) {
                if (first == null) first = lbl;
                last = lbl;
            }
        }
        if (first == null || last == null || first == last) return 0;

        // Determine slot count from maxLocals as an upper bound. Avoid slot 0
        // for non-static methods (this), but rename it anyway — renamer.
        int slots = mn.maxLocals;
        if (slots <= 0) return 0;

        List<LocalVariableNode> table = new ArrayList<>();
        Random r = new Random(
                ((long) cn.name.hashCode() << 32) ^ (((long) mn.name.hashCode()) * 31 + mn.desc.hashCode()));

        Map<Integer, String> seenDescBySlot = new HashMap<>();

        // Pre-seed "this" slot to Object descriptor for instance methods.
        boolean isStatic = (mn.access & Opcodes.ACC_STATIC) != 0;
        if (!isStatic) {
            seenDescBySlot.put(0, "L" + cn.name + ";");
        }

        // Assign slot descriptors based on the argument list.
        Type[] argTypes = Type.getArgumentTypes(mn.desc);
        int slotCursor = isStatic ? 0 : 1;
        for (Type t : argTypes) {
            seenDescBySlot.put(slotCursor, t.getDescriptor());
            slotCursor += t.getSize();
        }

        for (int slot = 0; slot < slots; slot++) {
            String desc = seenDescBySlot.getOrDefault(slot, "Ljava/lang/Object;");
            String name = pick(r);
            table.add(new LocalVariableNode(name, desc, null, first, last, slot));
        }

        mn.localVariables = table;
        return table.size();
    }

    private static String pick(Random r) {
        return CONFUSING_NAMES[r.nextInt(CONFUSING_NAMES.length)];
    }
}
