package obfuscator.transformers.phase1;

import obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * Renames local variable names to obfuscated values.
 */
public class LocalVariableTransformer {
    private static final Logger LOG = LoggerFactory.getLogger(LocalVariableTransformer.class);

    private final ClassPool pool;
    private final Random random = new Random(42);

    public LocalVariableTransformer(ClassPool pool) {
        this.pool = pool;
    }

    public void transform() {
        LOG.info("Starting local variable renaming...");
        int totalRenamed = 0;

        for (ClassNode cn : pool.getOwnClasses()) {
            for (MethodNode mn : cn.methods) {
                totalRenamed += renameLocals(mn);
            }
        }

        LOG.info("Local variable renaming complete: {} variables renamed", totalRenamed);
    }

    private int renameLocals(MethodNode mn) {
        if (mn.localVariables == null || mn.localVariables.isEmpty()) {
            return 0;
        }

        int count = 0;
        int varCounter = 0;

        for (LocalVariableNode lv : mn.localVariables) {
            // Skip 'this' parameter
            if ("this".equals(lv.name)) {
                continue;
            }

            // Skip parameters if HasSourceDebugInfo attribute exists
            if ((lv.index < mn.maxLocals - mn.maxStack) && 
                (mn.access & Opcodes.ACC_STATIC) == 0) {
                // Could be a parameter - still rename for obfuscation
            }

            // Generate obfuscated name
            lv.name = generateName(varCounter++);
            count++;
        }

        return count;
    }

    private String generateName(int index) {
        // Use short unicode characters that look similar but are different
        String[] chars = {
            "\u006C",  // l (Latin)
            "\u0456",  // i (Cyrillic)
            "\u043E",  // o (Cyrillic)
            "\u0049",  // I (Latin)
            "\u006F",  // o (Latin)
            "\u0031",  // 1
            "\u0030"   // 0
        };

        StringBuilder sb = new StringBuilder();
        int n = index;
        do {
            sb.append(chars[n % chars.length]);
            n /= chars.length;
        } while (n > 0);

        return sb.toString();
    }
}
