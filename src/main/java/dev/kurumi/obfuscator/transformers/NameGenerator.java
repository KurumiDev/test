package dev.kurumi.obfuscator.transformers;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

/**
 * Produces unique replacement identifiers according to the configured
 * {@link ObfuscatorConfig.NamingStrategy}. Tracks used names per namespace so
 * that generated identifiers never collide.
 */
public class NameGenerator {

    // Visually confusable characters that still form valid Java identifiers
    private static final char[] CONFUSE = new char[]{
            'I', 'l', '1', 'i', 'L', 'o', 'O', '0'
    };

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ObfuscatorConfig.NamingStrategy strategy;
    private final Set<String> used = new HashSet<>();
    private long counter;

    public NameGenerator(ObfuscatorConfig.NamingStrategy strategy) {
        this.strategy = strategy;
    }

    public String next() {
        String candidate;
        do {
            candidate = build(counter++);
        } while (!used.add(candidate));
        return candidate;
    }

    public void reserve(String name) {
        used.add(name);
    }

    private String build(long n) {
        return switch (strategy) {
            case ALPHABET -> alphabet(n);
            case UNICODE -> unicode(n);
            case CONFUSE -> confuse(n);
            case RANDOM_HEX -> hex();
        };
    }

    private static String alphabet(long n) {
        StringBuilder sb = new StringBuilder();
        n++;
        while (n > 0) {
            n--;
            sb.append((char) ('a' + (n % 26)));
            n /= 26;
        }
        return sb.reverse().toString();
    }

    private static String unicode(long n) {
        // Use homoglyph-heavy BMP code points that remain valid Java identifiers.
        // Java identifiers allow any Character.isJavaIdentifierStart/Part code point.
        StringBuilder sb = new StringBuilder();
        long idx = n + 1;
        int[] pool = {
                0x03B1, 0x03B2, 0x03B3, 0x03B4, 0x03B5, // greek lowercase
                0x03B6, 0x03B7, 0x03B8, 0x03B9, 0x03BA,
                0x03BB, 0x03BC, 0x03BD, 0x03BE, 0x03BF,
                0x03C0, 0x03C1, 0x03C3, 0x03C4, 0x03C5
        };
        while (idx > 0) {
            int r = (int) ((idx - 1) % pool.length);
            sb.appendCodePoint(pool[r]);
            idx = (idx - 1) / pool.length;
        }
        return sb.reverse().toString();
    }

    private static String confuse(long n) {
        StringBuilder sb = new StringBuilder();
        long idx = n + 1;
        while (idx > 0) {
            sb.append(CONFUSE[(int) ((idx - 1) % CONFUSE.length)]);
            idx = (idx - 1) / CONFUSE.length;
        }
        // Java identifier must not start with a digit
        if (Character.isDigit(sb.charAt(0))) sb.insert(0, 'I');
        return sb.toString();
    }

    private static String hex() {
        byte[] b = new byte[4];
        RANDOM.nextBytes(b);
        StringBuilder sb = new StringBuilder("a");
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
