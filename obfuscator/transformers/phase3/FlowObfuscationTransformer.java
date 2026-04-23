package obfuscator.transformers.phase3;

import obfuscator.core.ClassPool;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AnalyzerAdapter;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * FlowObfuscationTransformer - обфускация потока управления.
 * 
 * Техники:
 * 1. GOTO SPAGHETTI - разрезает метод на блоки и перемешивает их
 * 2. TABLE SWITCH DISPATCH - заменяет прямой поток на switch-диспетчеризацию
 * 3. EXCEPTION BASED FLOW - прячет код в catch-блоки
 * 4. FAKE DEAD CODE - добавляет реалистичный мёртвый код
 */
public class FlowObfuscationTransformer implements Opcodes {
    private static final Logger LOG = LoggerFactory.getLogger(FlowObfuscationTransformer.class);
    
    public enum Technique {
        GOTO_SPAGHETTI,
        TABLE_SWITCH,
        EXCEPTION_FLOW,
        DEAD_CODE,
        ALL
    }
    
    public enum Complexity {
        LOW(1), MEDIUM(3), HIGH(5);
        public final int level;
        Complexity(int level) { this.level = level; }
    }
    
    private final ClassPool pool;
    private final Technique technique;
    private final Complexity complexity;
    private final boolean addDeadCode;
    private final Random random = new Random(42);
    
    public FlowObfuscationTransformer(ClassPool pool, Technique technique, 
                                      Complexity complexity, boolean addDeadCode) {
        this.pool = pool;
        this.technique = technique;
        this.complexity = complexity;
        this.addDeadCode = addDeadCode;
    }
    
    public void transform() {
        LOG.info("Starting flow obfuscation (technique={}, complexity={})", technique, complexity);
        
        int transformedMethods = 0;
        
        for (ClassNode cn : pool.getOwnClasses()) {
            // Пропускаем интерфейсы, абстрактные классы
            if ((cn.access & ACC_INTERFACE) != 0 || (cn.access & ACC_ABSTRACT) != 0) {
                continue;
            }
            
            for (MethodNode mn : cn.methods) {
                // Пропускаем конструкторы, статические инициализаторы, абстрактные методы
                if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name) ||
                    (mn.access & ACC_ABSTRACT) != 0 || (mn.access & ACC_NATIVE) != 0 ||
                    mn.instructions.size() < 10) {
                    continue;
                }
                
                try {
                    boolean changed = false;
                    
                    if (technique == Technique.GOTO_SPAGHETTI || technique == Technique.ALL) {
                        changed |= applyGotoSpaghetti(cn, mn);
                    }
                    if (technique == Technique.TABLE_SWITCH || technique == Technique.ALL) {
                        changed |= applyTableSwitchDispatch(cn, mn);
                    }
                    if (technique == Technique.EXCEPTION_FLOW || technique == Technique.ALL) {
                        changed |= applyExceptionFlow(cn, mn);
                    }
                    if (addDeadCode && (technique == Technique.DEAD_CODE || technique == Technique.ALL)) {
                        changed |= addFakeDeadCode(cn, mn);
                    }
                    
                    if (changed) {
                        transformedMethods++;
                    }
                } catch (Exception e) {
                    LOG.debug("Failed to obfuscate method {}.{}{}: {}", 
                             cn.name, mn.name, mn.desc, e.getMessage());
                }
            }
        }
        
        LOG.info("Flow obfuscation complete: {} methods transformed", transformedMethods);
    }
    
    /**
     * GOTO SPAGHETTI - разрезает метод на блоки и перемешивает
     */
    private boolean applyGotoSpaghetti(ClassNode cn, MethodNode mn) {
        if (mn.instructions.size() < 15) return false;
        
        // Собираем все инструкции кроме Label, LineNumber, Frame
        List<AbstractInsnNode> codeInsns = new ArrayList<>();
        Map<AbstractInsnNode, LabelNode> insnToLabel = new IdentityHashMap<>();
        
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof LabelNode || insn instanceof LineNumberNode || 
                insn instanceof FrameNode) {
                continue;
            }
            codeInsns.add(insn);
        }
        
        if (codeInsns.size() < 10) return false;
        
        // Разрезаем на блоки по 3-5 инструкций
        int blockSize = 3 + random.nextInt(3);
        List<List<AbstractInsnNode>> blocks = new ArrayList<>();
        
        for (int i = 0; i < codeInsns.size(); i += blockSize) {
            List<AbstractInsnNode> block = new ArrayList<>();
            for (int j = i; j < Math.min(i + blockSize, codeInsns.size()); j++) {
                block.add(codeInsns.get(j));
            }
            blocks.add(block);
        }
        
        if (blocks.size() < 3) return false;
        
        // Перемешиваем блоки
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < blocks.size(); i++) order.add(i);
        Collections.shuffle(order, random);
        
        // Создаём новые label для каждого блока
        List<LabelNode> blockLabels = new ArrayList<>();
        for (int i = 0; i < blocks.size(); i++) {
            blockLabels.add(new LabelNode(new Label()));
        }
        
        // Строим новый список инструкций
        InsnList newInstructions = new InsnList();
        
        // Добавляем переменную состояния для dispatch
        LabelNode startLabel = new LabelNode(new Label());
        newInstructions.add(startLabel);
        
        // Добавляем блоки в перемешанном порядке с GOTO между ними
        for (int i = 0; i < order.size(); i++) {
            int blockIdx = order.get(i);
            
            // Label начала блока
            newInstructions.add(blockLabels.get(blockIdx));
            
            // Инструкции блока
            for (AbstractInsnNode insn : blocks.get(blockIdx)) {
                newInstructions.add(insn.clone(null));
            }
            
            // GOTO к следующему блоку (если не последний)
            if (i < order.size() - 1) {
                int nextBlockIdx = order.get(i + 1);
                newInstructions.add(new JumpInsnNode(GOTO, blockLabels.get(nextBlockIdx)));
            }
        }
        
        mn.instructions = newInstructions;
        mn.tryCatchBlocks.clear(); // Очищаем старые try-catch
        
        return true;
    }
    
    /**
     * TABLE SWITCH DISPATCH - заменяет поток на switch с состоянием
     */
    private boolean applyTableSwitchDispatch(ClassNode cn, MethodNode mn) {
        if (mn.instructions.size() < 20) return false;
        
        // Проверяем что нет локальных переменных с типом long/double (усложняет анализ)
        if (hasLongOrDoubleLocals(mn)) return false;
        
        // Собираем инструкции
        List<AbstractInsnNode> codeInsns = new ArrayList<>();
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof LabelNode || insn instanceof LineNumberNode || 
                insn instanceof FrameNode) {
                continue;
            }
            codeInsns.add(insn);
        }
        
        if (codeInsns.size() < 15) return false;
        
        // Разрезаем на блоки
        int blockSize = 4 + random.nextInt(3);
        List<List<AbstractInsnNode>> blocks = new ArrayList<>();
        
        for (int i = 0; i < codeInsns.size(); i += blockSize) {
            List<AbstractInsnNode> block = new ArrayList<>();
            for (int j = i; j < Math.min(i + blockSize, codeInsns.size()); j++) {
                block.add(codeInsns.get(j));
            }
            blocks.add(block);
        }
        
        if (blocks.size() < 3) return false;
        
        // Добавляем локальную переменную состояния
        int stateVar = mn.maxLocals++;
        
        // Строим новый метод
        InsnList newInstructions = new InsnList();
        
        // Инициализация состояния = 0
        newInstructions.add(new InsnNode(ICONST_0));
        newInstructions.add(new VarInsnNode(ISTORE, stateVar));
        
        // Главный цикл while(true)
        LabelNode loopStart = new LabelNode(new Label());
        LabelNode loopEnd = new LabelNode(new Label());
        newInstructions.add(loopStart);
        
        // Switch по состоянию
        LabelNode defaultLabel = new LabelNode(new Label());
        LabelNode[] caseLabels = new LabelNode[blocks.size()];
        for (int i = 0; i < blocks.size(); i++) {
            caseLabels[i] = new LabelNode(new Label());
        }
        
        // Загружаем состояние
        newInstructions.add(new VarInsnNode(ILOAD, stateVar));
        
        // Создаём tableswitch
        newInstructions.add(new TableSwitchInsnNode(0, blocks.size() - 1, defaultLabel, caseLabels));
        
        // Добавляем кейсы
        for (int i = 0; i < blocks.size(); i++) {
            newInstructions.add(caseLabels[i]);
            
            // Инструкции блока
            for (AbstractInsnNode insn : blocks.get(i)) {
                newInstructions.add(insn.clone(null));
            }
            
            // Устанавливаем следующее состояние (случайное или 0 для выхода)
            int nextState = (i < blocks.size() - 1) ? (i + 1) : -1;
            if (nextState >= 0) {
                newInstructions.add(new LdcInsnNode(nextState));
                newInstructions.add(new VarInsnNode(ISTORE, stateVar));
            } else {
                // Выход из цикла
                newInstructions.add(new JumpInsnNode(GOTO, loopEnd));
            }
        }
        
        // Default case - выход
        newInstructions.add(defaultLabel);
        newInstructions.add(new JumpInsnNode(GOTO, loopEnd));
        
        // Конец цикла
        newInstructions.add(loopEnd);
        
        mn.instructions = newInstructions;
        mn.tryCatchBlocks.clear();
        
        return true;
    }
    
    /**
     * EXCEPTION BASED FLOW - прячет настоящий код в catch блок
     */
    private boolean applyExceptionFlow(ClassNode cn, MethodNode mn) {
        if (mn.instructions.size() < 15) return false;
        
        // Находим точку для вставки try-catch
        AbstractInsnNode insertPoint = findInsertionPoint(mn);
        if (insertPoint == null) return false;
        
        // Создаём исключение которое всегда выбрасывается
        LabelNode tryStart = new LabelNode(new Label());
        LabelNode tryEnd = new LabelNode(new Label());
        LabelNode catchStart = new LabelNode(new Label());
        LabelNode catchEnd = new LabelNode(new Label());
        
        // Вставляем try { throw new Exception(); } catch (Exception e) { original_code }
        InsnList tryBlock = new InsnList();
        tryBlock.add(tryStart);
        tryBlock.add(new TypeInsnNode(NEW, "java/lang/Exception"));
        tryBlock.add(new InsnNode(DUP));
        tryBlock.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Exception", "<init>", "()V", false));
        tryBlock.add(new InsnNode(ATHROW));
        tryBlock.add(tryEnd);
        
        // Catch блок содержит оригинальный код
        InsnList catchBlock = new InsnList();
        catchBlock.add(catchStart);
        
        // Сохраняем исключение в локальную переменную
        int excVar = mn.maxLocals++;
        catchBlock.add(new VarInsnNode(ASTORE, excVar));
        
        // Копируем оригинальные инструкции
        for (AbstractInsnNode insn : mn.instructions) {
            catchBlock.add(insn.clone(null));
        }
        
        catchBlock.add(catchEnd);
        
        // Добавляем try-catch таблицу
        CatchBlockNode catchNode = new CatchBlockNode(tryStart, tryEnd, catchStart, "java/lang/Exception");
        mn.tryCatchBlocks.add(catchNode);
        
        // Заменяем инструкции
        mn.instructions.clear();
        mn.instructions.add(tryBlock);
        mn.instructions.add(catchBlock);
        
        return true;
    }
    
    /**
     * Добавляет реалистичный мёртвый код
     */
    private boolean addFakeDeadCode(ClassNode cn, MethodNode mn) {
        // Находим случайную точку для вставки
        AbstractInsnNode insertPoint = findInsertionPoint(mn);
        if (insertPoint == null) return false;
        
        // Генерируем мёртвый код
        InsnList deadCode = new InsnList();
        
        // Создаём объекты которые никогда не используются
        deadCode.add(new TypeInsnNode(NEW, "java/lang/StringBuilder"));
        deadCode.add(new InsnNode(DUP));
        deadCode.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
        deadCode.add(new LdcInsnNode("dead"));
        deadCode.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", 
                                        "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
        deadCode.add(new InsnNode(POP));
        
        // Математические операции результат которых игнорируется
        deadCode.add(new LdcInsnNode(random.nextInt(1000)));
        deadCode.add(new LdcInsnNode(random.nextInt(1000)));
        deadCode.add(new InsnNode(IADD));
        deadCode.add(new InsnNode(POP));
        
        // Вставляем мёртвый код
        mn.instructions.insert(insertPoint, deadCode);
        
        return true;
    }
    
    private AbstractInsnNode findInsertionPoint(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn.getOpcode() >= ICONST_M1 && insn.getOpcode() <= ICONST_5) {
                return insn;
            }
        }
        return mn.instructions.getFirst();
    }
    
    private boolean hasLongOrDoubleLocals(MethodNode mn) {
        if (mn.desc == null) return false;
        Type[] args = Type.getArgumentTypes(mn.desc);
        for (Type arg : args) {
            if (arg.getSize() == 2) return true;
        }
        Type returnType = Type.getReturnType(mn.desc);
        if (returnType.getSize() == 2) return true;
        return false;
    }
}
