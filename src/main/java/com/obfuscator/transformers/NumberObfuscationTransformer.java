package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * NumberObfuscationTransformer — обфусцирует числовые константы
 * Заменяет числа на вычисления которые дают тот же результат
 * 
 * Техники:
 * - XOR/NOT: 42 → ~(-43)
 * - Arithmetic: 42 → (6 * 7)
 * - Bit shifts: 42 → (168 >> 2)
 * - Opaque math: 42 → ((x * (x+1)) / 2) где x=9
 */
public class NumberObfuscationTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(NumberObfuscationTransformer.class);
    private static final Random RANDOM = new Random();

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public NumberObfuscationTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        logger.info("Starting number obfuscation...");

        int transformed = 0;
        boolean onlyMagicNumbers = config.isOnlyMagicNumbers();

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;

            for (MethodNode method : cn.methods) {
                if (method.instructions == null || (method.access & Opcodes.ACC_ABSTRACT) != 0) continue;
                
                // Пропускаем <clinit> чтобы не ломать инициализацию констант
                if (method.name.equals("<clinit>")) continue;

                transformed += obfuscateMethod(method, onlyMagicNumbers, cn.name);
            }
        }

        logger.info("Number obfuscation completed. Transformed {} constants", transformed);
    }

    @Override
    public String getName() {
        return "NumberObfuscationTransformer";
    }

    private int obfuscateMethod(MethodNode method, boolean onlyMagicNumbers, String className) {
        int count = 0;
        InsnList newInstructions = new InsnList();

        for (AbstractInsnNode insn : method.instructions) {
            int opcode = insn.getOpcode();
            
            if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
                int value = opcode - Opcodes.ICONST_0;
                if (opcode == Opcodes.ICONST_M1) value = -1;
                
                if (shouldObfuscate(value, onlyMagicNumbers)) {
                    replaceWithObfuscated(newInstructions, value, className);
                    count++;
                    continue;
                }
            } else if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                IntInsnNode push = (IntInsnNode) insn;
                int value = push.operand;
                
                if (shouldObfuscate(value, onlyMagicNumbers)) {
                    replaceWithObfuscated(newInstructions, value, className);
                    count++;
                    continue;
                }
            } else if (opcode == Opcodes.LDC) {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (ldc.cst instanceof Integer) {
                    int value = (Integer) ldc.cst;
                    if (shouldObfuscate(value, onlyMagicNumbers)) {
                        replaceWithObfuscated(newInstructions, value, className);
                        count++;
                        continue;
                    }
                } else if (ldc.cst instanceof Long) {
                    long value = (Long) ldc.cst;
                    if (shouldObfuscate((int)Math.abs(value), onlyMagicNumbers)) {
                        replaceWithObfuscatedLong(newInstructions, value, className);
                        count++;
                        continue;
                    }
                }
            }

            newInstructions.add(insn);
        }

        if (count > 0) {
            method.instructions = newInstructions;
        }

        return count;
    }

    private boolean shouldObfuscate(int value, boolean onlyMagicNumbers) {
        if (onlyMagicNumbers) {
            // Не обфусцируем маленькие числа и распространенные значения
            // которые часто используются как loop counters или индексы
            return Math.abs(value) > 10;
        }
        // Не обфусцируем -1, 0, 1, 2 - они слишком часто используются
        return value < -1 || value > 2;
    }

    private void replaceWithObfuscated(InsnList instructions, int value, String className) {
        int technique = RANDOM.nextInt(5);
        
        switch (technique) {
            case 0:
                // XOR/NOT: value = ~(-value - 1)
                instructions.add(new LdcInsnNode(-value - 1));
                instructions.add(new InsnNode(Opcodes.INEG));
                instructions.add(new InsnNode(Opcodes.ICONST_M1));
                instructions.add(new InsnNode(Opcodes.IXOR));
                break;
                
            case 1:
                // Bit shift: value = (value << 2) >> 2
                instructions.add(new LdcInsnNode(value << 2));
                instructions.add(new LdcInsnNode(2));
                instructions.add(new InsnNode(Opcodes.ISHR));
                break;
                
            case 2:
                // Arithmetic: value = (value * 1) + 0
                int factor = 2 + RANDOM.nextInt(5);
                int remainder = value % factor;
                int base = value - remainder;
                instructions.add(new LdcInsnNode(base / factor));
                instructions.add(new LdcInsnNode(factor));
                instructions.add(new InsnNode(Opcodes.IMUL));
                if (remainder != 0) {
                    instructions.add(new LdcInsnNode(remainder));
                    instructions.add(new InsnNode(Opcodes.IADD));
                }
                break;
                
            case 3:
                // XOR с ключом: value = value ^ key ^ key
                int key = RANDOM.nextInt(1000) + 1;
                instructions.add(new LdcInsnNode(value ^ key));
                instructions.add(new LdcInsnNode(key));
                instructions.add(new InsnNode(Opcodes.IXOR));
                break;
                
            case 4:
                // Opaque math: используем математические тождества
                // value = ((value + 1) * (value - 1) + 1) / value для value != 0
                if (value != 0 && Math.abs(value) > 2) {
                    instructions.add(new LdcInsnNode(value + 1));
                    instructions.add(new LdcInsnNode(value - 1));
                    instructions.add(new InsnNode(Opcodes.IMUL));
                    instructions.add(new LdcInsnNode(1));
                    instructions.add(new InsnNode(Opcodes.IADD));
                    instructions.add(new LdcInsnNode(value));
                    instructions.add(new InsnNode(Opcodes.IDIV));
                } else {
                    // Fallback к простому XOR
                    int xorKey = RANDOM.nextInt(1000) + 1;
                    instructions.add(new LdcInsnNode(value ^ xorKey));
                    instructions.add(new LdcInsnNode(xorKey));
                    instructions.add(new InsnNode(Opcodes.IXOR));
                }
                break;
        }
    }

    private void replaceWithObfuscatedLong(InsnList instructions, long value, String className) {
        int technique = RANDOM.nextInt(3);
        
        switch (technique) {
            case 0:
                // XOR
                long key = RANDOM.nextLong();
                instructions.add(new LdcInsnNode(value ^ key));
                instructions.add(new LdcInsnNode(key));
                instructions.add(new InsnNode(Opcodes.LXOR));
                break;
                
            case 1:
                // Shift
                instructions.add(new LdcInsnNode(value << 2));
                instructions.add(new LdcInsnNode(2L));
                instructions.add(new InsnNode(Opcodes.LSHR));
                break;
                
            case 2:
                // Arithmetic
                long factor = 2 + RANDOM.nextInt(5);
                long remainder = value % factor;
                long base = value - remainder;
                instructions.add(new LdcInsnNode(base / factor));
                instructions.add(new LdcInsnNode(factor));
                instructions.add(new InsnNode(Opcodes.LMUL));
                if (remainder != 0) {
                    instructions.add(new LdcInsnNode(remainder));
                    instructions.add(new InsnNode(Opcodes.LADD));
                }
                break;
        }
    }
}
