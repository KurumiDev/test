package obfuscator.transformers.phase3;

import obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * OpaquePredicateTransformer - добавляет непрозрачные предикаты.
 * 
 * Категории предикатов от слабых к сильным:
 * 1. ALIASING - основаны на identityHashCode
 * 2. RUNTIME_STATE - основаны на runtime состоянии (Runtime, Thread, System)
 * 3. CROSS_METHOD - вычисляются в другом методе и хранятся в поле
 */
public class OpaquePredicateTransformer implements Opcodes {
    private static final Logger LOG = LoggerFactory.getLogger(OpaquePredicateTransformer.class);
    
    public enum Category {
        ALIASING,
        RUNTIME_STATE,
        CROSS_METHOD
    }
    
    private final ClassPool pool;
    private final Set<Category> categories;
    private final double density; // доля if-блоков куда добавлять predicates
    private final Random random = new Random(42);
    
    // Поле для cross-method предикатов
    private String opaqueFieldName;
    
    public OpaquePredicateTransformer(ClassPool pool, Set<Category> categories, double density) {
        this.pool = pool;
        this.categories = categories;
        this.density = density;
    }
    
    public void transform() {
        LOG.info("Starting opaque predicate injection (categories={}, density={})", categories, density);
        
        // Сначала создаём поле для cross-method предикатов в первом классе
        initCrossMethodField();
        
        int predicatesAdded = 0;
        
        for (ClassNode cn : pool.getOwnClasses()) {
            if ((cn.access & ACC_INTERFACE) != 0 || (cn.access & ACC_ABSTRACT) != 0) {
                continue;
            }
            
            for (MethodNode mn : cn.methods) {
                if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name) ||
                    (mn.access & ACC_ABSTRACT) != 0 || (mn.access & ACC_NATIVE) != 0 ||
                    mn.instructions.size() < 10) {
                    continue;
                }
                
                try {
                    predicatesAdded += addOpaquePredicates(cn, mn);
                } catch (Exception e) {
                    LOG.debug("Failed to add predicates to {}.{}{}: {}", 
                             cn.name, mn.name, mn.desc, e.getMessage());
                }
            }
        }
        
        LOG.info("Opaque predicate injection complete: {} predicates added", predicatesAdded);
    }
    
    private void initCrossMethodField() {
        // Создаём поле для хранения opaque значения
        opaqueFieldName = generateFieldName();
        
        // Добавляем поле в первый подходящий класс
        for (ClassNode cn : pool.getOwnClasses()) {
            if ((cn.access & ACC_INTERFACE) == 0) {
                FieldNode fn = new FieldNode(
                    ACC_PRIVATE | ACC_STATIC | ACC_FINAL,
                    opaqueFieldName,
                    "I",
                    null,
                    1 // Всегда true значение (но это не очевидно статически)
                );
                cn.fields.add(fn);
                
                // Также добавляем инициализацию в <clinit>
                addToClinit(cn);
                break;
            }
        }
    }
    
    private void addToClinit(ClassNode cn) {
        MethodNode clinit = null;
        for (MethodNode mn : cn.methods) {
            if ("<clinit>".equals(mn.name)) {
                clinit = mn;
                break;
            }
        }
        
        if (clinit == null) {
            // Создаём новый <clinit>
            clinit = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
            cn.methods.add(clinit);
        }
        
        // Добавляем инициализацию поля
        InsnList init = new InsnList();
        init.add(new LdcInsnNode(computeOpaqueValue()));
        init.add(new FieldInsnNode(PUTSTATIC, cn.name, opaqueFieldName, "I"));
        clinit.instructions.insert(init);
    }
    
    private int addOpaquePredicates(ClassNode cn, MethodNode mn) {
        int added = 0;
        List<JumpInsnNode> jumps = new ArrayList<>();
        
        // Находим все условные переходы
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof JumpInsnNode jump) {
                int opcode = jump.getOpcode();
                if (opcode == IFEQ || opcode == IFNE || opcode == IFLT || 
                    opcode == IFGE || opcode == IFGT || opcode == IFLE ||
                    opcode == IF_ICMPEQ || opcode == IF_ICMPNE ||
                    opcode == IF_ACMPEQ || opcode == IF_ACMPNE ||
                    opcode == IFNULL || opcode == IFNONNULL) {
                    jumps.add(jump);
                }
            }
        }
        
        // Случайно выбираем какие jumps обфусцировать
        for (JumpInsnNode jump : jumps) {
            if (random.nextDouble() > density) continue;
            
            Category category = categories.toArray(new Category[0])[random.nextInt(categories.size())];
            
            switch (category) {
                case ALIASING -> addAliasingPredicate(mn, jump);
                case RUNTIME_STATE -> addRuntimeStatePredicate(mn, jump);
                case CROSS_METHOD -> addCrossMethodPredicate(cn, mn, jump);
            }
            added++;
        }
        
        return added;
    }
    
    /**
     * ALIASING предикат - использует identityHashCode
     * if (obj != null && System.identityHashCode(obj) == System.identityHashCode(obj))
     * Статический анализатор не знает что это всегда true
     */
    private void addAliasingPredicate(MethodNode mn, JumpInsnNode jump) {
        InsnList predicate = new InsnList();
        
        // Создаём объект
        LabelNode objLabel = new LabelNode();
        predicate.add(new TypeInsnNode(NEW, "java/lang/Object"));
        predicate.add(new InsnNode(DUP));
        predicate.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        predicate.add(new VarInsnNode(ASTORE, mn.maxLocals++));
        
        // Сравниваем identityHashCode
        predicate.add(new FieldInsnNode(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;"));
        predicate.add(new VarInsnNode(ALOAD, mn.maxLocals - 1));
        predicate.add(new MethodInsnNode(INVOKESTATIC, "java/lang/System", 
                                        "identityHashCode", "(Ljava/lang/Object;)I", false));
        predicate.add(new VarInsnNode(ALOAD, mn.maxLocals - 1));
        predicate.add(new MethodInsnNode(INVOKESTATIC, "java/lang/System", 
                                        "identityHashCode", "(Ljava/lang/Object;)I", false));
        predicate.add(new JumpInsnNode(IF_ICMPNE, jump.label)); // Всегда false branch
        
        mn.instructions.insert(jump, predicate);
    }
    
    /**
     * RUNTIME_STATE предикат - использует runtime информацию
     * if (Runtime.getRuntime().availableProcessors() > 0) - всегда true
     */
    private void addRuntimeStatePredicate(MethodNode mn, JumpInsnNode jump) {
        InsnList predicate = new InsnList();
        
        int choice = random.nextInt(4);
        
        switch (choice) {
            case 0 -> {
                // Runtime.availableProcessors() > 0
                predicate.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Runtime", 
                                                "getRuntime", "()Ljava/lang/Runtime;", false));
                predicate.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Runtime", 
                                                "availableProcessors", "()I", false));
                predicate.add(new JumpInsnNode(IFLE, jump.label));
            }
            case 1 -> {
                // Thread.currentThread().getStackTrace().length > 0
                predicate.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Thread", 
                                                "currentThread", "()Ljava/lang/Thread;", false));
                predicate.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Thread", 
                                                "getStackTrace", "()[Ljava/lang/StackTraceElement;", false));
                predicate.add(new InsnNode(ARRAYLENGTH));
                predicate.add(new JumpInsnNode(IFLE, jump.label));
            }
            case 2 -> {
                // System.currentTimeMillis() > 0
                predicate.add(new MethodInsnNode(INVOKESTATIC, "java/lang/System", 
                                                "currentTimeMillis", "()J", false));
                predicate.add(new LdcInsnNode(0L));
                predicate.add(new JumpInsnNode(LCMP, null));
                predicate.add(new JumpInsnNode(IFLE, jump.label));
            }
            case 3 -> {
                // ClassLoader.getSystemClassLoader() != null
                predicate.add(new MethodInsnNode(INVOKESTATIC, "java/lang/ClassLoader", 
                                                "getSystemClassLoader", "()Ljava/lang/ClassLoader;", false));
                predicate.add(new JumpInsnNode(IFNULL, jump.label));
            }
        }
        
        mn.instructions.insert(jump, predicate);
    }
    
    /**
     * CROSS_METHOD предикат - использует поле вычисленное в другом месте
     */
    private void addCrossMethodPredicate(ClassNode cn, MethodNode mn, JumpInsnNode jump) {
        InsnList predicate = new InsnList();
        
        // Загружаем поле
        predicate.add(new FieldInsnNode(GETSTATIC, cn.name, opaqueFieldName, "I"));
        predicate.add(new LdcInsnNode(0));
        predicate.add(new JumpInsnNode(IF_ICMPLE, jump.label)); // Если <= 0, идём на fake branch
        
        mn.instructions.insert(jump, predicate);
    }
    
    private String generateFieldName() {
        String[] names = {"_opaque", "_state", "_flag", "_cond", "_pred"};
        return names[random.nextInt(names.length)] + random.nextInt(100);
    }
    
    private int computeOpaqueValue() {
        // Вычисляем значение которое всегда > 0 но не очевидно статически
        return Math.abs(new Random().nextInt()) % 100 + 1;
    }
}
