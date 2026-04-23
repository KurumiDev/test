package obfuscator.transformers.phase2;

import obfuscator.core.ClassPool;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Obfuscates numbers using XOR and bitwise operations.
 */
public class NumberObfuscationTransformer {
    private static final Logger LOG = LoggerFactory.getLogger(NumberObfuscationTransformer.class);

    private final ClassPool pool;
    private final int minValue;
    private final boolean useXor;
    private final boolean useBitwise;
    private final Random random = new Random(42);

    public NumberObfuscationTransformer(ClassPool pool, int minValue, boolean useXor, boolean useBitwise) {
        this.pool = pool;
        this.minValue = minValue;
        this.useXor = useXor;
        this.useBitwise = useBitwise;
    }

    public void transform() {
        LOG.info("Starting number obfuscation (min={}, xor={}, bitwise={})...", 
                minValue, useXor, useBitwise);
        int totalTransformed = 0;

        for (ClassNode cn : pool.getOwnClasses()) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                totalTransformed += obfuscateMethod(mn);
            }
        }

        LOG.info("Number obfuscation complete: {} numbers transformed", totalTransformed);
    }

    private int obfuscateMethod(MethodNode mn) {
        int count = 0;
        List<AbstractInsnNode> toProcess = new ArrayList<>();

        // Find all number pushes
        for (AbstractInsnNode insn : mn.instructions) {
            int opcode = insn.getOpcode();
            
            // Skip small numbers (often loop counters)
            if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
                int value = opcode - Opcodes.ICONST_0;
                if (Math.abs(value) < minValue) continue;
                toProcess.add(insn);
            } else if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
                int value = ((IntInsnNode) insn).operand;
                if (Math.abs(value) < minValue) continue;
                toProcess.add(insn);
            } else if (opcode == Opcodes.LDC) {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (ldc.cst instanceof Integer i) {
                    if (Math.abs(i) < minValue) continue;
                    toProcess.add(insn);
                } else if (ldc.cst instanceof Long l) {
                    if (Math.abs(l) < minValue) continue;
                    toProcess.add(insn);
                } else if (ldc.cst instanceof Float f) {
                    toProcess.add(insn);
                } else if (ldc.cst instanceof Double d) {
                    toProcess.add(insn);
                }
            }
        }

        // Replace with obfuscated versions
        for (AbstractInsnNode insn : toProcess) {
            if (obfuscateMethod(mn, insn)) {
                count++;
            }
        }

        return count;
    }

    private boolean obfuscateMethod(MethodNode mn, AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        InsnList replacement = new InsnList();

        switch (opcode) {
            case Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1,
                 Opcodes.ICONST_2, Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
                 Opcodes.BIPUSH, Opcodes.SIPUSH -> {
                int value = switch (opcode) {
                    case Opcodes.ICONST_M1 -> -1;
                    case Opcodes.ICONST_0 -> 0;
                    case Opcodes.ICONST_1 -> 1;
                    case Opcodes.ICONST_2 -> 2;
                    case Opcodes.ICONST_3 -> 3;
                    case Opcodes.ICONST_4 -> 4;
                    case Opcodes.ICONST_5 -> 5;
                    default -> ((IntInsnNode) insn).operand;
                };
                obfuscateInt(replacement, value);
            }

            case Opcodes.LDC -> {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (ldc.cst instanceof Integer i) {
                    obfuscateInt(replacement, i);
                } else if (ldc.cst instanceof Long l) {
                    obfuscateLong(replacement, l);
                } else if (ldc.cst instanceof Float f) {
                    obfuscateFloat(replacement, f);
                } else if (ldc.cst instanceof Double d) {
                    obfuscateDouble(replacement, d);
                } else {
                    return false;
                }
            }

            default -> {
                return false;
            }
        }

        mn.instructions.insert(insn, replacement);
        mn.instructions.remove(insn);
        return true;
    }

    private void obfuscateInt(InsnList out, int value) {
        if (useXor && random.nextBoolean()) {
            // XOR obfuscation: value = key ^ encrypted
            int key = random.nextInt();
            int encrypted = value ^ key;
            out.add(new IntInsnNode(Opcodes.SIPUSH, key & 0x7FFF));
            out.add(new IntInsnNode(Opcodes.SIPUSH, encrypted & 0x7FFF));
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, 
                "java/lang/Integer", "bitCount", "(I)I", false));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Integer", "intValue", "()I", false));
            out.add(new IntInsnNode(Opcodes.SIPUSH, key >>> 16));
            out.add(new IntInsnNode(Opcodes.SIPUSH, encrypted >>> 16));
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/Integer", "rotateLeft", "(II)I", false));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Integer", "intValue", "()I", false));
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                "java/lang/Integer", "reverse", "(I)I", false));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                "java/lang/Integer", "intValue", "()I", false));
            // Simpler version:
            out.clear();
            int k = random.nextInt();
            out.add(new IntInsnNode(Opcodes.SIPUSH, k));
            out.add(new IntInsnNode(Opcodes.SIPUSH, value ^ k));
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                getRuntimeClass(), "xorDecode", "(II)I", false));
        } else if (useBitwise) {
            // Bitwise obfuscation: value = (a + b) - c | d & e
            int a = random.nextInt();
            int b = value - a + 100;
            out.add(new IntInsnNode(Opcodes.SIPUSH, a & 0x7FFF));
            out.add(new IntInsnNode(Opcodes.SIPUSH, b & 0x7FFF));
            out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                getRuntimeClass(), "addDecode", "(II)I", false));
        } else {
            // Simple push
            if (value >= -32768 && value <= 32767) {
                out.add(new IntInsnNode(Opcodes.SIPUSH, value));
            } else {
                out.add(new LdcInsnNode(value));
            }
        }
    }

    private void obfuscateLong(InsnList out, long value) {
        long key = random.nextLong();
        out.add(new LdcInsnNode(key));
        out.add(new LdcInsnNode(value ^ key));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            getRuntimeClass(), "xorDecodeLong", "(JJ)J", false));
    }

    private void obfuscateFloat(InsnList out, float value) {
        int key = random.nextInt();
        int encoded = Float.floatToRawIntBits(value) ^ key;
        out.add(new IntInsnNode(Opcodes.SIPUSH, key));
        out.add(new IntInsnNode(Opcodes.SIPUSH, encoded));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            getRuntimeClass(), "decodeFloat", "(II)F", false));
    }

    private void obfuscateDouble(InsnList out, double value) {
        long key = random.nextLong();
        long encoded = Double.doubleToRawLongBits(value) ^ key;
        out.add(new LdcInsnNode(key));
        out.add(new LdcInsnNode(encoded));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
            getRuntimeClass(), "decodeDouble", "(JJ)D", false));
    }

    private String getRuntimeClass() {
        // Will be injected at runtime
        return "com/obf/runtime/NumberHelper";
    }
}
