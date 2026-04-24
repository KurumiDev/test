package dev.kurumi.obfuscator.transformers;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Per-class polymorphic byte-stream decoder.
 *
 * <p>Every transformer that emits a runtime XOR-based byte-stream decoder
 * ({@link IndyCallTransformer}, {@link IndyFieldTransformer},
 * {@link BlobStringTransformer}) picks a variant from {@link #variantFor(String)}
 * keyed on the owning class's internal name. The variant is a concrete
 * <em>pair</em> of a Java-side {@link #xorByteStream encrypt} function and a
 * matching ASM emission routine for the decoder inner loop
 * ({@link #emitKeyUpdate}, {@link #emitMask}). The same class always resolves
 * to the same variant so decryption round-trips.
 *
 * <p>Four variants ship out of the box, all symmetric XOR-based so encrypt
 * and decrypt share the same per-byte operation. They differ in the mask
 * function and key-update function, which is what changes the <em>shape</em>
 * of the decoded bytecode a reverse engineer has to reconstruct:
 *
 * <ul>
 *   <li><b>V0 &mdash; LCG classic.</b> mask = {@code k & 0xFF};
 *       {@code k = k * 0x45D9F3B + 0x119DE1F3}. Was the single shared shape
 *       before this change; kept for one of the four arms.</li>
 *   <li><b>V1 &mdash; XORshift32.</b> mask = {@code k & 0xFF};
 *       {@code k ^= k << 13; k ^= k >>> 17; k ^= k << 5}. Three shifts plus
 *       two XORs, no arithmetic multiplies &mdash; different Hamming profile
 *       and different static-analysis fingerprint than V0.</li>
 *   <li><b>V2 &mdash; rotate-plus-add with position-mixed mask.</b> mask =
 *       {@code (k ^ (i * 0x9E3779B9)) & 0xFF};
 *       {@code k = rotateLeft(k, 11) + 0xDEADBEEF}. Introduces a
 *       position-dependent mask so constant-propagation on the loop body
 *       doesn't collapse to a pure state machine over {@code k}.</li>
 *   <li><b>V3 &mdash; plaintext-feedback LCG.</b> mask = {@code k & 0xFF};
 *       {@code k = k * 0x45D9F3B + (plain[i] & 0xFF) + 0x119DE1F3}. Key
 *       schedule depends on the <em>decoded</em> byte, so the attacker can
 *       no longer symbolically pre-compute the keystream without knowing the
 *       plaintext.</li>
 * </ul>
 *
 * <p>A reverse engineer who extracts <em>one</em> class's decoder body into
 * a standalone tool will only decrypt that class's arguments. Any other
 * class with a different variant index will require a different decoder
 * shape, not just a different key.
 */
public final class DecoderPolymorphism {

    private DecoderPolymorphism() {}

    public static final int VARIANT_COUNT = 4;

    /**
     * Deterministic per-class variant selector. FNV-1a hash of the
     * internal class name modulo {@link #VARIANT_COUNT}. Same class name
     * always returns the same variant so encryptor/decoder agree.
     */
    public static int variantFor(String internalName) {
        long h = 0xCBF29CE484222325L;
        for (int i = 0; i < internalName.length(); i++) {
            h ^= internalName.charAt(i);
            h *= 0x100000001B3L;
        }
        // SplitMix64 finalizer so similar prefixes disperse evenly.
        h = (h ^ (h >>> 30)) * 0xBF58476D1CE4E5B9L;
        h = (h ^ (h >>> 27)) * 0x94D049BB133111EBL;
        h ^= (h >>> 31);
        int idx = (int) (h & 0x7FFFFFFFL) % VARIANT_COUNT;
        return idx;
    }

    /**
     * Java-side XOR stream cipher. Produces the ciphertext the matching
     * bytecode decoder will invert. Variant-specific in both mask and key
     * update.
     *
     * @param raw     plaintext bytes
     * @param seed    initial key; variant-agnostic
     * @param variant 0..{@link #VARIANT_COUNT}-1
     * @return fresh byte[] of the same length as {@code raw}
     */
    public static byte[] xorByteStream(byte[] raw, int seed, int variant) {
        byte[] out = new byte[raw.length];
        int k = seed;
        for (int i = 0; i < raw.length; i++) {
            int mask;
            switch (variant) {
                case 2:
                    mask = (k ^ (i * 0x9E3779B9)) & 0xFF;
                    break;
                default:
                    mask = k & 0xFF;
            }
            int c = (raw[i] & 0xFF) ^ mask;
            out[i] = (byte) c;
            // plain byte (raw[i]) used by V3 feedback
            k = updateKey(k, i, raw[i] & 0xFF, variant);
        }
        return out;
    }

    private static int updateKey(int k, int i, int plainByte, int variant) {
        switch (variant) {
            case 1:
                k ^= k << 13;
                k ^= k >>> 17;
                k ^= k << 5;
                return k;
            case 2:
                return Integer.rotateLeft(k, 11) + 0xDEADBEEF;
            case 3:
                return k * 0x45D9F3B + plainByte + 0x119DE1F3;
            default:
                return k * 0x45D9F3B + 0x119DE1F3;
        }
    }

    /**
     * Emits the bytecode that computes the per-byte XOR mask and leaves
     * one int on the operand stack. The caller is expected to have loaded
     * the ciphertext byte and will apply {@code IXOR} and {@code I2B} to
     * produce the plaintext byte.
     *
     * @param il      instruction list to append to
     * @param kSlot   local index holding the running key
     * @param iSlot   local index holding the byte position
     */
    public static void emitMask(InsnList il, int kSlot, int iSlot, int variant) {
        if (variant == 2) {
            // (k ^ (i * 0x9E3779B9)) & 0xFF
            il.add(new VarInsnNode(Opcodes.ILOAD, kSlot));
            il.add(new VarInsnNode(Opcodes.ILOAD, iSlot));
            il.add(new LdcInsnNode(Integer.valueOf(0x9E3779B9)));
            il.add(new InsnNode(Opcodes.IMUL));
            il.add(new InsnNode(Opcodes.IXOR));
            il.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
            il.add(new InsnNode(Opcodes.IAND));
        } else {
            // k & 0xFF
            il.add(new VarInsnNode(Opcodes.ILOAD, kSlot));
            il.add(new IntInsnNode(Opcodes.SIPUSH, 0xFF));
            il.add(new InsnNode(Opcodes.IAND));
        }
    }

    /**
     * Emits the bytecode that advances the running key for the next
     * iteration. The resulting integer is stored back into {@code kSlot}.
     *
     * <p>For variant 3 the caller must make the just-decoded plaintext byte
     * available in {@code plainSlot} (as an int in 0..255) before calling
     * this method. For other variants {@code plainSlot} is ignored.
     */
    public static void emitKeyUpdate(InsnList il, int kSlot, int iSlot,
                                     int plainSlot, int variant) {
        switch (variant) {
            case 1:
                emitXorShift32(il, kSlot);
                break;
            case 2:
                emitRotateAdd(il, kSlot);
                break;
            case 3:
                emitLcgPlainFeedback(il, kSlot, plainSlot);
                break;
            default:
                emitLcgClassic(il, kSlot);
        }
    }

    private static void emitLcgClassic(InsnList il, int kSlot) {
        // k = k * 0x45D9F3B + 0x119DE1F3
        il.add(new VarInsnNode(Opcodes.ILOAD, kSlot));
        il.add(new LdcInsnNode(Integer.valueOf(0x45D9F3B)));
        il.add(new InsnNode(Opcodes.IMUL));
        il.add(new LdcInsnNode(Integer.valueOf(0x119DE1F3)));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new VarInsnNode(Opcodes.ISTORE, kSlot));
    }

    private static void emitXorShift32(InsnList il, int kSlot) {
        // k ^= k << 13; k ^= k >>> 17; k ^= k << 5;
        emitXorShiftStep(il, kSlot, 13, Opcodes.ISHL);
        emitXorShiftStep(il, kSlot, 17, Opcodes.IUSHR);
        emitXorShiftStep(il, kSlot, 5, Opcodes.ISHL);
    }

    private static void emitXorShiftStep(InsnList il, int kSlot, int shift, int shiftOp) {
        // k = k ^ (k <shiftOp> shift)
        il.add(new VarInsnNode(Opcodes.ILOAD, kSlot));
        il.add(new VarInsnNode(Opcodes.ILOAD, kSlot));
        il.add(new IntInsnNode(Opcodes.BIPUSH, shift));
        il.add(new InsnNode(shiftOp));
        il.add(new InsnNode(Opcodes.IXOR));
        il.add(new VarInsnNode(Opcodes.ISTORE, kSlot));
    }

    private static void emitRotateAdd(InsnList il, int kSlot) {
        // k = Integer.rotateLeft(k, 11) + 0xDEADBEEF
        il.add(new VarInsnNode(Opcodes.ILOAD, kSlot));
        il.add(new IntInsnNode(Opcodes.BIPUSH, 11));
        il.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESTATIC, "java/lang/Integer", "rotateLeft",
                "(II)I", false));
        il.add(new LdcInsnNode(Integer.valueOf(0xDEADBEEF)));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new VarInsnNode(Opcodes.ISTORE, kSlot));
    }

    private static void emitLcgPlainFeedback(InsnList il, int kSlot, int plainSlot) {
        // k = k * 0x45D9F3B + plain + 0x119DE1F3
        il.add(new VarInsnNode(Opcodes.ILOAD, kSlot));
        il.add(new LdcInsnNode(Integer.valueOf(0x45D9F3B)));
        il.add(new InsnNode(Opcodes.IMUL));
        il.add(new VarInsnNode(Opcodes.ILOAD, plainSlot));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new LdcInsnNode(Integer.valueOf(0x119DE1F3)));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new VarInsnNode(Opcodes.ISTORE, kSlot));
    }
}
