package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.*;

/**
 * InvokeDynamicTransformer — использует invokedynamic для обфускации вызовов
 * 
 * ВАЖНО: НЕ применять к классам с лямбдами
 */
public class InvokeDynamicTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(InvokeDynamicTransformer.class);
    private static final Random RANDOM = new Random();

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public InvokeDynamicTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        if (config.isAutoDetectLambdas()) {
            logger.info("Checking for lambda usage...");
        }
        
        logger.info("Starting invokedynamic transformation...");

        int transformed = 0;

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;

            // Пропускаем классы с лямбдами
            if (hasLambdas(cn)) {
                logger.debug("Skipping {} - contains lambdas", cn.name);
                continue;
            }

            for (MethodNode method : cn.methods) {
                if (method.instructions == null || (method.access & Opcodes.ACC_ABSTRACT) != 0) continue;
                if (method.name.equals("<init>") || method.name.equals("<clinit>")) continue;

                if (convertToInvokeDynamic(method, cn.name)) {
                    transformed++;
                }
            }
        }

        logger.info("Invokedynamic transformation completed. Transformed {} methods", transformed);
    }

    @Override
    public String getName() {
        return "InvokeDynamicTransformer";
    }

    private boolean hasLambdas(ClassNode cn) {
        // Проверяем наличие методов lambda$ или bootstrap методов
        for (MethodNode method : cn.methods) {
            if (method.name.startsWith("lambda$")) {
                return true;
            }
        }
        
        // Проверяем наличие BootstrapMethods атрибута
        if (cn.visibleAnnotations != null) {
            for (AnnotationNode ann : cn.visibleAnnotations) {
                if (ann.desc.contains("Lambda")) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean convertToInvokeDynamic(MethodNode method, String className) {
        InsnList newInstructions = new InsnList();
        int converted = 0;

        for (AbstractInsnNode insn : method.instructions) {
            if (insn.getOpcode() == Opcodes.INVOKESTATIC && RANDOM.nextDouble() < 0.3) {
                MethodInsnNode invoke = (MethodInsnNode) insn;
                
                // Не конвертируем важные методы
                if (isCriticalMethod(invoke)) {
                    newInstructions.add(insn);
                    continue;
                }

                // Создаем invokedynamic вместо INVOKESTATIC
                Handle bootstrap = new Handle(
                    Opcodes.H_INVOKESTATIC,
                    "com/obfuscator/runtime/InvokeDynamicBootstrap",
                    "bootstrap",
                    "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;)Ljava/lang/invoke/CallSite;",
                    false
                );

                // Аргументы для bootstrap метода
                Object[] bsmArgs = new Object[] {
                    invoke.owner,
                    invoke.name,
                    invoke.desc
                };

                // Загружаем аргументы которые были на стеке
                Type methodType = Type.getMethodType(invoke.desc);
                Type[] argTypes = methodType.getArgumentTypes();

                // Пересоздаем загрузку аргументов (уже были на стеке)
                // Просто добавляем invokedynamic
                InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(
                    invoke.name,
                    invoke.desc,
                    bootstrap,
                    bsmArgs
                );

                newInstructions.add(indy);
                converted++;
            } else {
                newInstructions.add(insn);
            }
        }

        if (converted > 0) {
            method.instructions = newInstructions;
            return true;
        }

        return false;
    }

    private boolean isCriticalMethod(MethodInsnNode invoke) {
        // Не трогаем критические методы
        String criticalOwners[] = {
            "java/lang/System",
            "java/lang/Thread",
            "java/lang/Object",
            "java/lang/Class",
            "java/lang/String"
        };

        for (String owner : criticalOwners) {
            if (invoke.owner.equals(owner)) {
                return true;
            }
        }

        // Не трогаем методы которые начинаются с access$ (синтетические доступы)
        if (invoke.name.startsWith("access$")) {
            return true;
        }

        return false;
    }
}
