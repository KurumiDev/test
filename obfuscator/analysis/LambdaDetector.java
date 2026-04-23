package analysis;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * Detects classes that use lambda expressions via invokedynamic.
 * LambdaMetafactory is the bootstrap for Java 8+ lambdas.
 */
public class LambdaDetector {
    private static final Logger LOG = LoggerFactory.getLogger(LambdaDetector.class);

    private static final String LAMBDA_METAFACTORY = "java/lang/invoke/LambdaMetafactory";
    private static final String ALT_METAFACTORY = "java/lang/invoke/StringConcatFactory";

    /**
     * Check if a class contains lambda expressions
     */
    public static boolean hasLambdas(ClassNode cn) {
        for (MethodNode mn : cn.methods) {
            if (hasLambdas(mn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a method contains lambda expressions
     */
    public static boolean hasLambdas(MethodNode mn) {
        if (mn.instructions == null) return false;

        for (var insn : mn.instructions) {
            if (insn instanceof InvokeDynamicInsnNode idyn) {
                // Lambdas use LambdaMetafactory or StringConcatFactory as bootstrap
                if (idyn.bsm != null) {
                    String bsmOwner = idyn.bsm.getOwner();
                    if (LAMBDA_METAFACTORY.equals(bsmOwner) || 
                        ALT_METAFACTORY.equals(bsmOwner)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Scan all classes and return set of classes with lambdas
     */
    public static Set<String> scanClasses(Iterable<ClassNode> classes) {
        Set<String> classesWithLambdas = new HashSet<>();
        int totalLambdas = 0;

        for (ClassNode cn : classes) {
            if (hasLambdas(cn)) {
                classesWithLambdas.add(cn.name);
                totalLambdas++;
            }
        }

        LOG.info("Found {} classes with lambda expressions", totalLambdas);
        return classesWithLambdas;
    }

    /**
     * Count total invokedynamic instructions in a class (including non-lambda)
     */
    public static int countInvokeDynamic(ClassNode cn) {
        int count = 0;
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) continue;
            for (var insn : mn.instructions) {
                if (insn instanceof InvokeDynamicInsnNode) {
                    count++;
                }
            }
        }
        return count;
    }
}
