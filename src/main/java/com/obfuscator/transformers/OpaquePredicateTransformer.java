package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * OpaquePredicateTransformer — добавляет opaque predicates
 * 
 * Типы:
 * - MATH — математические тождества
 * - RUNTIME — runtime зависимые предикаты
 * - MIXED — комбинация
 */
public class OpaquePredicateTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(OpaquePredicateTransformer.class);
    private static final Random RANDOM = new Random();

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public OpaquePredicateTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        ObfuscatorConfig.OpaquePredicateType type = config.getOpaquePredicateType();
        logger.info("Starting opaque predicate insertion (type: {})...", type);

        int inserted = 0;

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;

            for (MethodNode method : cn.methods) {
                if (method.instructions == null || (method.access & Opcodes.ACC_ABSTRACT) != 0) continue;
                if (method.name.equals("<init>") || method.name.equals("<clinit>")) continue;

                inserted += insertOpaquePredicates(method, type.name());
            }
        }

        logger.info("Opaque predicate insertion completed. Inserted {} predicates", inserted);
    }

    @Override
    public String getName() {
        return "OpaquePredicateTransformer";
    }

    private int insertOpaquePredicates(MethodNode method, String type) {
        int count = 0;
        InsnList newInstructions = new InsnList();

        for (AbstractInsnNode insn : method.instructions) {
            newInstructions.add(insn);

            // Вставляем opaque predicate перед инструкциями потока управления
            if (isControlFlowInstruction(insn) && RANDOM.nextDouble() < 0.2) {
                LabelNode skipLabel = new LabelNode();
                
                switch (type) {
                    case "MATH":
                        insertMathPredicate(newInstructions, skipLabel);
                        break;
                    case "RUNTIME":
                        insertRuntimePredicate(newInstructions, skipLabel);
                        break;
                    case "MIXED":
                        if (RANDOM.nextBoolean()) {
                            insertMathPredicate(newInstructions, skipLabel);
                        } else {
                            insertRuntimePredicate(newInstructions, skipLabel);
                        }
                        break;
                }
                count++;
            }
        }

        if (count > 0) {
            method.instructions = newInstructions;
        }

        return count;
    }

    private boolean isControlFlowInstruction(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return opcode == Opcodes.IFEQ || opcode == Opcodes.IFNE || opcode == Opcodes.IFLT ||
               opcode == Opcodes.IFGE || opcode == Opcodes.IFGT || opcode == Opcodes.IFLE ||
               opcode == Opcodes.IF_ICMPEQ || opcode == Opcodes.IF_ICMPNE ||
               opcode == Opcodes.IF_ICMPLT || opcode == Opcodes.IF_ICMPGE ||
               opcode == Opcodes.IF_ICMPGT || opcode == Opcodes.IF_ICMPLE ||
               opcode == Opcodes.IF_ACMPEQ || opcode == Opcodes.IF_ACMPNE ||
               opcode == Opcodes.GOTO || opcode == Opcodes.TABLESWITCH ||
               opcode == Opcodes.LOOKUPSWITCH || opcode == Opcodes.IRETURN ||
               opcode == Opcodes.LRETURN || opcode == Opcodes.FRETURN ||
               opcode == Opcodes.DRETURN || opcode == Opcodes.ARETURN ||
               opcode == Opcodes.RETURN;
    }

    private void insertMathPredicate(InsnList instructions, LabelNode skipLabel) {
        int predicateType = RANDOM.nextInt(5);
        
        switch (predicateType) {
            case 0:
                // (x * (x + 1)) % 2 == 0 для любого x
                // Произведение двух последовательных чисел всегда четное
                instructions.add(new LdcInsnNode(RANDOM.nextInt(1000)));
                instructions.add(new LdcInsnNode(1));
                instructions.add(new InsnNode(Opcodes.IADD));
                instructions.add(new InsnNode(Opcodes.IMUL));
                instructions.add(new LdcInsnNode(2));
                instructions.add(new InsnNode(Opcodes.IREM));
                instructions.add(new JumpInsnNode(Opcodes.IFEQ, skipLabel));
                // Dead branch
                instructions.add(new LdcInsnNode(-1));
                instructions.add(new InsnNode(Opcodes.POP));
                instructions.add(skipLabel);
                break;

            case 1:
                // (a | b) >= (a & b) всегда true
                instructions.add(new LdcInsnNode(RANDOM.nextInt(1000)));
                instructions.add(new LdcInsnNode(RANDOM.nextInt(1000)));
                instructions.add(new InsnNode(Opcodes.IOR));
                instructions.add(new LdcInsnNode(RANDOM.nextInt(1000)));
                instructions.add(new LdcInsnNode(RANDOM.nextInt(1000)));
                instructions.add(new InsnNode(Opcodes.IAND));
                instructions.add(new InsnNode(Opcodes.ISUB));
                instructions.add(new JumpInsnNode(Opcodes.IFGE, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;

            case 2:
                // x ^ x == 0
                int val = RANDOM.nextInt(1000);
                instructions.add(new LdcInsnNode(val));
                instructions.add(new LdcInsnNode(val));
                instructions.add(new InsnNode(Opcodes.IXOR));
                instructions.add(new JumpInsnNode(Opcodes.IFEQ, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;

            case 3:
                // (x >> 31) & 1 == 0 для положительных x
                instructions.add(new LdcInsnNode(Math.abs(RANDOM.nextInt())));
                instructions.add(new LdcInsnNode(31));
                instructions.add(new InsnNode(Opcodes.ISHR));
                instructions.add(new LdcInsnNode(1));
                instructions.add(new InsnNode(Opcodes.IAND));
                instructions.add(new JumpInsnNode(Opcodes.IFEQ, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;

            case 4:
                // ((x + y) * (x - y)) == (x*x - y*y)
                int x = RANDOM.nextInt(100);
                int y = RANDOM.nextInt(100);
                instructions.add(new LdcInsnNode(x + y));
                instructions.add(new LdcInsnNode(x - y));
                instructions.add(new InsnNode(Opcodes.IMUL));
                instructions.add(new LdcInsnNode(x * x - y * y));
                instructions.add(new InsnNode(Opcodes.ISUB));
                instructions.add(new JumpInsnNode(Opcodes.IFEQ, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;
        }
    }

    private void insertRuntimePredicate(InsnList instructions, LabelNode skipLabel) {
        int predicateType = RANDOM.nextInt(4);
        
        switch (predicateType) {
            case 0:
                // Runtime.getRuntime().availableProcessors() > 0 всегда true
                instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false));
                instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "availableProcessors", "()I", false));
                instructions.add(new JumpInsnNode(Opcodes.IFGT, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;

            case 1:
                // Thread.currentThread().getId() > 0 всегда true
                instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;", false));
                instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "getId", "()J", false));
                instructions.add(new LdcInsnNode(0L));
                instructions.add(new InsnNode(Opcodes.LCMP));
                instructions.add(new JumpInsnNode(Opcodes.IFGT, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;

            case 2:
                // System.currentTimeMillis() > 0 (всегда true после 1970)
                instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "currentTimeMillis", "()J", false));
                instructions.add(new LdcInsnNode(0L));
                instructions.add(new InsnNode(Opcodes.LCMP));
                instructions.add(new JumpInsnNode(Opcodes.IFGT, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;

            case 3:
                // Integer.valueOf(1).equals(Integer.valueOf(1)) всегда true
                instructions.add(new LdcInsnNode(1));
                instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                instructions.add(new LdcInsnNode(1));
                instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "equals", "(Ljava/lang/Object;)Z", false));
                instructions.add(new JumpInsnNode(Opcodes.IFNE, skipLabel));
                // Dead branch
                instructions.add(new InsnNode(Opcodes.NOP));
                instructions.add(skipLabel);
                break;
        }
    }
}
