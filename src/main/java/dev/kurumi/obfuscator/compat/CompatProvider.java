package dev.kurumi.obfuscator.compat;

import java.util.Set;

/**
 * A platform/framework-specific source of rename exemptions. Implementations
 * contribute annotation descriptors, method signatures, and superclass names
 * whose members must not be renamed.
 */
public interface CompatProvider {

    String name();

    /** Annotation descriptors (e.g. {@code Lorg/bukkit/event/EventHandler;}). */
    Set<String> exemptAnnotations();

    /** Method signatures {@code name+desc} that must not be renamed. */
    Set<String> exemptMethodSignatures();

    /** Superclasses/interfaces whose subtypes get automatic method exemptions. */
    Set<String> exemptClassSuperTypes();
}
