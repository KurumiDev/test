package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NameGeneratorTest {

    @Test
    void alphabetProducesUniqueNames() {
        NameGenerator g = new NameGenerator(ObfuscatorConfig.NamingStrategy.ALPHABET);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            String n = g.next();
            assertNotNull(n);
            assertTrue(seen.add(n), "duplicate: " + n);
        }
        assertEquals(1000, seen.size());
    }

    @Test
    void confuseProducesOnlyConfusableChars() {
        NameGenerator g = new NameGenerator(ObfuscatorConfig.NamingStrategy.CONFUSE);
        for (int i = 0; i < 100; i++) {
            String n = g.next();
            for (char c : n.toCharArray()) {
                assertTrue("IlioO01L".indexOf(c) >= 0, "unexpected char: " + c);
            }
        }
    }

    @Test
    void hexIsValidIdentifier() {
        NameGenerator g = new NameGenerator(ObfuscatorConfig.NamingStrategy.RANDOM_HEX);
        for (int i = 0; i < 50; i++) {
            String n = g.next();
            assertTrue(Character.isJavaIdentifierStart(n.charAt(0)));
            for (int j = 1; j < n.length(); j++) {
                assertTrue(Character.isJavaIdentifierPart(n.charAt(j)));
            }
        }
    }

    @Test
    void unicodeIsValidIdentifier() {
        NameGenerator g = new NameGenerator(ObfuscatorConfig.NamingStrategy.UNICODE);
        for (int i = 0; i < 50; i++) {
            String n = g.next();
            assertTrue(Character.isJavaIdentifierStart(n.codePointAt(0)));
        }
    }
}
