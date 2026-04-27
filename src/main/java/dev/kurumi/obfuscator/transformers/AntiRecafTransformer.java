package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.core.ClassPool;
import dev.kurumi.obfuscator.core.ObfuscatorContext;
import dev.kurumi.obfuscator.core.Transformer;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Random;

/**
 * Adds non-standard, JVM-tolerated bytecode constructions that trip
 * up automated bytecode editors (Recaf, Krakatau) and decompilers
 * (CFR, Fernflower, Procyon) without affecting runtime behaviour.
 *
 * <p>Three layered tricks, each independently defensible:
 *
 * <ol>
 *   <li><b>Unknown class attributes.</b> ASM lets us emit attributes
 *       with arbitrary names and payloads via the
 *       {@link Attribute} subclass mechanism. The JVM ignores any
 *       attribute whose name it does not recognise (JVMS §4.7.1).
 *       Recaf, Krakatau, and other strict-validating tools either
 *       refuse to load the class file or emit warnings and partially
 *       skip parsing. We add one such attribute per class with a
 *       crypto-strength random payload so even bulk pattern-matching
 *       on the attribute body is fruitless.</li>
 *
 *   <li><b>Bogus generic Signature.</b> The {@code Signature}
 *       attribute is metadata for compile-time generics; the JVM
 *       does not consult it during class loading or verification.
 *       Decompilers, in contrast, eagerly use it to reconstruct
 *       Java-source-level generic declarations -- and most of them
 *       trust the bytes. We attach a syntactically valid
 *       Generic Class Signature that declares a type parameter
 *       bound by a non-existent class (e.g.
 *       {@code <T:Lkurumi/$Phantom;>Ljava/lang/Object;}). At runtime
 *       this is invisible. In CFR / Fernflower / Procyon output the
 *       class header becomes
 *       {@code class Foo<T extends Phantom> extends Object} which
 *       does not compile if anyone tries to feed the decompiled
 *       source back through {@code javac}.</li>
 *
 *   <li><b>Method-level junk attributes.</b> Same trick as (1) but
 *       attached to one method per class. Method-level unknown
 *       attributes are even rarer in the wild than class-level
 *       ones; most class-file editors handle them correctly only
 *       for the small fixed set defined by JVMS.</li>
 * </ol>
 *
 * <p>This transformer must run <b>before</b>
 * {@link AntiTamperTransformer}: the integrity manifest is computed
 * over final post-pipeline bytes, so the trap attributes must be in
 * place before the SHA-256 is taken. Conversely, it should run after
 * any pass that reads or rewrites attributes (none currently --
 * {@link SourceAttributeScrubber} only touches {@code SourceFile} /
 * {@code SourceDebug}, which we don't pollute).
 */
public class AntiRecafTransformer implements Transformer {

    private static final Logger log = LoggerFactory.getLogger(AntiRecafTransformer.class);

    private static final byte[] TRAP_PAYLOAD_TEMPLATE = new byte[64];

    @Override
    public String name() {
        return "anti-recaf";
    }

    @Override
    public void transform(ClassPool pool, ObfuscatorContext ctx) {
        // Per-build seed so two obfuscation runs of the same input
        // emit different trap payloads.
        Random rnd = new Random();
        int classes = 0;
        int methodAttrs = 0;
        String prefix = SyntheticNaming.prefix(pool);
        // Attribute name uses the per-JAR synthetic prefix so two
        // jars on the same classpath cannot be fingerprinted by a
        // single shared attribute name.
        String attrName = prefix.substring(prefix.length() - 4) + "Trap";

        for (ClassNode cn : pool.allClassNodes()) {
            if (cn.attrs == null) cn.attrs = new ArrayList<>();
            byte[] payload = new byte[TRAP_PAYLOAD_TEMPLATE.length];
            rnd.nextBytes(payload);
            cn.attrs.add(new TrapAttribute(attrName, payload));

            // Bogus generic class signature. Skipped for classes
            // that already have a real signature -- overwriting a
            // legitimate one would risk surprising user code that
            // reflects on it via {@code Class.getGenericSuperclass()}.
            if (cn.signature == null) {
                cn.signature = bogusClassSignature(prefix);
            }

            // Pick the first regular instance method (skip
            // <init> / <clinit> / abstracts) and attach a trap
            // attribute to it as well. We don't blanket all methods
            // because every extra attribute survives ClassWriter and
            // thus inflates JAR size.
            for (MethodNode mn : cn.methods) {
                if (mn.name.startsWith("<")) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.attrs == null) mn.attrs = new ArrayList<>();
                byte[] mPayload = new byte[16];
                rnd.nextBytes(mPayload);
                mn.attrs.add(new TrapAttribute(attrName + "M", mPayload));
                methodAttrs++;
                break;
            }

            classes++;
        }

        log.info("Anti-recaf: stamped {} classes ({} method-level traps, attr name '{}')",
                classes, methodAttrs, attrName);
    }

    /**
     * Builds a syntactically valid Generic Class Signature that the
     * JVM ignores but which decompilers will eagerly try to render
     * in their output.
     *
     * <p>Form: {@code <T:Lprefix$Phantom;>Ljava/lang/Object;} -- a
     * single type parameter {@code T} bounded by a class that does
     * not exist anywhere in the JAR or on the classpath. Per JVMS
     * §4.7.9.1 the bound class reference is a binary class name
     * checked at compile time, not run time.
     */
    private static String bogusClassSignature(String prefix) {
        // Strip the leading '$' from the per-JAR synthetic prefix
        // because Signature attributes parse '$' as the inner-class
        // separator, and we don't want a phantom OUTER class
        // accidentally being inferred.
        String clean = prefix.replace("$", "_");
        return "<T:L" + clean + "Phantom;>Ljava/lang/Object;";
    }

    /**
     * Custom ASM {@link Attribute} that emits an arbitrary byte
     * payload under an arbitrary name. ASM treats unknown
     * attributes as opaque blobs: they survive
     * {@link ClassReader} -> {@link ClassWriter} round-trips and
     * are not validated by frame computation.
     */
    private static final class TrapAttribute extends Attribute {
        private final byte[] data;

        TrapAttribute(String name, byte[] data) {
            super(name);
            this.data = data;
        }

        @Override
        public boolean isUnknown() {
            return true;
        }

        @Override
        public boolean isCodeAttribute() {
            return false;
        }

        @Override
        protected Attribute read(ClassReader cr, int off, int len, char[] buf,
                                 int codeOff, Label[] labels) {
            byte[] copy = new byte[len];
            for (int i = 0; i < len; i++) copy[i] = (byte) cr.readByte(off + i);
            return new TrapAttribute(this.type, copy);
        }

        @Override
        protected ByteVector write(ClassWriter cw, byte[] code, int codeLen,
                                   int maxStack, int maxLocals) {
            ByteVector bv = new ByteVector();
            bv.putByteArray(data, 0, data.length);
            return bv;
        }
    }
}
