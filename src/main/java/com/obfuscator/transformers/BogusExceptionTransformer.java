package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * BogusExceptionTransformer — добавляет bogus exception-based flow
 * 
 * Техника: оборачиваем код в try-catch который никогда не срабатывает
 * но ломает анализ потока управления декомпилятора
 */
public class BogusExceptionTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(BogusExceptionTransformer.class);
    private static final Random RANDOM = new Random();

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public BogusExceptionTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        logger.info("Starting bogus exception transformation...");

        int transformed = 0;

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;

            for (MethodNode method : cn.methods) {
                if (method.instructions == null || (method.access & Opcodes.ACC_ABSTRACT) != 0) continue;
                if (method.name.equals("<init>") || method.name.equals("<clinit>")) continue;

                if (RANDOM.nextDouble() < 0.3) { // 30% методов
                    transformMethod(method, cn.name);
                    transformed++;
                }
            }
        }

        logger.info("Bogus exception transformation completed. Transformed {} methods", transformed);
    }

    @Override
    public String getName() {
        return "BogusExceptionTransformer";
    }

    private void transformMethod(MethodNode method, String className) {
        InsnList originalInstructions = method.instructions;
        InsnList newInstructions = new InsnList();

        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handlerStart = new LabelNode();
        LabelNode handlerEnd = new LabelNode();
        LabelNode afterHandler = new LabelNode();

        // Opaque predicate - условие которое всегда false
        // if (false) throw new Exception();
        newInstructions.add(new LdcInsnNode(0));
        newInstructions.add(new JumpInsnNode(Opcodes.IFEQ, tryStart));

        // Dead branch - выброс исключения которое никогда не случится
        newInstructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Exception"));
        newInstructions.add(new InsnNode(Opcodes.DUP));
        newInstructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Exception", "<init>", "()V", false));
        newInstructions.add(new InsnNode(Opcodes.ATHROW));

        // Try block
        newInstructions.add(tryStart);
        
        // Копируем оригинальные инструкции
        for (AbstractInsnNode insn : originalInstructions) {
            newInstructions.add(insn.clone(null));
        }

        newInstructions.add(tryEnd);
        newInstructions.add(new JumpInsnNode(Opcodes.GOTO, afterHandler));

        // Handler block
        newInstructions.add(handlerStart);
        // Просто игнорируем исключение и возвращаемся
        newInstructions.add(new InsnNode(Opcodes.POP));
        newInstructions.add(new JumpInsnNode(Opcodes.GOTO, afterHandler));
        newInstructions.add(handlerEnd);

        // После handler
        newInstructions.add(afterHandler);

        method.instructions = newInstructions;

        // Добавляем exception table entry
        method.tryCatchBlocks.add(new TryCatchBlockNode(tryStart, tryEnd, handlerStart, "java/lang/Exception"));
    }
}
