package com.obfuscator.transformers;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * FlowObfuscationTransformer — обфусцирует поток управления
 * 
 * Техники:
 * - BOGUS_JUMPS — мёртвые переходы
 * - EXCEPTION — exception-based flow
 * - GOTO_SPAGHETTI — разрезание блоков и GOTO
 * - SWITCH_DISPATCH — switch-based dispatch
 */
public class FlowObfuscationTransformer implements Transformer {
    private static final Logger logger = LoggerFactory.getLogger(FlowObfuscationTransformer.class);
    private static final Random RANDOM = new Random();

    private final ClassPool classPool;
    private final ObfuscatorConfig config;

    public FlowObfuscationTransformer(ClassPool classPool, ObfuscatorConfig config) {
        this.classPool = classPool;
        this.config = config;
    }

    @Override
    public void transform(ClassPool pool) {
        ObfuscatorConfig.FlowTechnique technique = config.getFlowTechnique();
        logger.info("Starting flow obfuscation (technique: {})...", technique);

        int transformed = 0;

        for (ClassNode cn : classPool.getObfuscatableClasses()) {
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;

            for (MethodNode method : cn.methods) {
                if (method.instructions == null || (method.access & Opcodes.ACC_ABSTRACT) != 0) continue;
                if (method.name.equals("<init>") || method.name.equals("<clinit>")) continue;

                switch (technique) {
                    case BOGUS_JUMPS:
                        if (addBogusJumps(method)) transformed++;
                        break;
                    case EXCEPTION:
                        if (addExceptionFlow(method)) transformed++;
                        break;
                    case GOTO_SPAGHETTI:
                        if (addGotoSpaghetti(method)) transformed++;
                        break;
                    case SWITCH_DISPATCH:
                        if (addSwitchDispatch(method)) transformed++;
                        break;
                    case ALL:
                        int count = 0;
                        if (addBogusJumps(method)) count++;
                        if (addGotoSpaghetti(method)) count++;
                        if (count > 0) transformed++;
                        break;
                }
            }
        }

        logger.info("Flow obfuscation completed. Transformed {} methods", transformed);
    }

    @Override
    public String getName() {
        return "FlowObfuscationTransformer";
    }

    private boolean addBogusJumps(MethodNode method) {
        if (method.instructions.size() < 5) return false;

        InsnList newInstructions = new InsnList();
        LabelNode bogusLabel = new LabelNode();

        for (AbstractInsnNode insn : method.instructions) {
            newInstructions.add(insn);

            // Добавляем bogus jump после каждого RETURN-подобного
            if (insn.getOpcode() >= Opcodes.IRETURN && insn.getOpcode() <= Opcodes.RETURN) {
                // Мертвый код после return
                newInstructions.add(new JumpInsnNode(Opcodes.GOTO, bogusLabel));
                newInstructions.add(bogusLabel);
                newInstructions.add(new LdcInsnNode(0));
                newInstructions.add(new IntInsnNode(Opcodes.BIPUSH, 1));
                newInstructions.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, new LabelNode()));
            }
        }

        if (newInstructions.size() > method.instructions.size()) {
            method.instructions = newInstructions;
            return true;
        }
        return false;
    }

    private boolean addExceptionFlow(MethodNode method) {
        if (method.instructions.size() < 3) return false;

        InsnList original = method.instructions;
        InsnList newInstructions = new InsnList();

        LabelNode tryStart = new LabelNode();
        LabelNode tryEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode after = new LabelNode();

        // Opaque predicate: всегда false
        newInstructions.add(new LdcInsnNode(0));
        newInstructions.add(new JumpInsnNode(Opcodes.IFNE, tryStart));

        // Dead branch - никогда не выполнится
        newInstructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"));
        newInstructions.add(new InsnNode(Opcodes.DUP));
        newInstructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false));
        newInstructions.add(new InsnNode(Opcodes.ATHROW));

        newInstructions.add(tryStart);

        // Копируем оригинал
        for (AbstractInsnNode insn : original) {
            newInstructions.add(insn.clone(null));
        }

        newInstructions.add(tryEnd);
        newInstructions.add(new JumpInsnNode(Opcodes.GOTO, after));

        newInstructions.add(handler);
        newInstructions.add(new InsnNode(Opcodes.POP));
        newInstructions.add(after);

        method.instructions = newInstructions;
        method.tryCatchBlocks.add(new TryCatchBlockNode(tryStart, tryEnd, handler, "java/lang/RuntimeException"));

        return true;
    }

    private boolean addGotoSpaghetti(MethodNode method) {
        if (method.instructions.size() < 10) return false;

        InsnList newInstructions = new InsnList();
        List<LabelNode> labels = new ArrayList<>();

        // Создаем ярлыки для разных точек
        for (int i = 0; i < 5; i++) {
            labels.add(new LabelNode());
        }

        int instructionCount = 0;
        LabelNode currentLabel = null;

        for (AbstractInsnNode insn : method.instructions) {
            // Периодически вставляем goto spaghetti
            if (instructionCount > 0 && instructionCount % 5 == 0 && RANDOM.nextDouble() < 0.3) {
                LabelNode nextLabel = new LabelNode();
                LabelNode skipLabel = new LabelNode();

                // Opaque predicate: всегда true
                newInstructions.add(new LdcInsnNode(1));
                newInstructions.add(new JumpInsnNode(Opcodes.IFEQ, skipLabel));

                // Нормальный путь
                newInstructions.add(nextLabel);

                // Вставляем dead label где-то
                if (RANDOM.nextBoolean()) {
                    newInstructions.add(labels.get(RANDOM.nextInt(labels.size())));
                }

                newInstructions.add(insn);

                newInstructions.add(skipLabel);
            } else {
                newInstructions.add(insn);
            }

            instructionCount++;
        }

        if (newInstructions.size() > method.instructions.size()) {
            method.instructions = newInstructions;
            return true;
        }
        return false;
    }

    private boolean addSwitchDispatch(MethodNode method) {
        if (method.instructions.size() < 8) return false;

        // Эта техника сложнее - требует анализа базовых блоков
        // Для простоты добавляем только opaque switch

        InsnList newInstructions = new InsnList();
        LabelNode defaultCase = new LabelNode();
        LabelNode realCase = new LabelNode();
        LabelNode endSwitch = new LabelNode();

        // Opaque switch: всегда case 1
        newInstructions.add(new LdcInsnNode(1));
        TableSwitchInsnNode switchInsn = new TableSwitchInsnNode(0, 2, defaultCase, realCase);
        newInstructions.add(switchInsn);

        // Default case - мертвый код
        newInstructions.add(defaultCase);
        newInstructions.add(new LdcInsnNode(-1));
        newInstructions.add(new JumpInsnNode(Opcodes.GOTO, endSwitch));

        // Real case - настоящий код
        newInstructions.add(realCase);
        for (AbstractInsnNode insn : method.instructions) {
            newInstructions.add(insn);
        }

        newInstructions.add(endSwitch);

        method.instructions = newInstructions;
        return true;
    }
}
