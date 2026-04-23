package cli;

import core.Obfuscator;
import core.MappingTable;
import picocli.CommandLine;
import picocli.CommandLine.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "obfuscator", mixinStandardHelpOptions = true, version = "1.0.0",
         description = "Java Bytecode Obfuscator - ASM 9.7, Java 21")
public class Main implements Callable<Integer> {

    @Option(names = {"-i", "--input"}, required = true, description = "Input JAR file")
    private Path input;

    @Option(names = {"-o", "--output"}, required = true, description = "Output JAR file")
    private Path output;

    @Option(names = {"-c", "--config"}, description = "Configuration file (HOCON)")
    private Path config;

    @Option(names = {"-l", "--libraries"}, split = ",", description = "Library JARs for analysis")
    private List<Path> libraries = new ArrayList<>();

    @Option(names = {"--mapping"}, description = "Save mapping table to file")
    private Path mapping;

    @Option(names = {"--strategy"}, description = "Naming strategy: ALPHABET, UNICODE, CONFUSE, SLASH_TRICK, KEYWORD_ABUSE",
            defaultValue = "ALPHABET")
    private String strategy;

    @Option(names = {"--string-strength"}, description = "String encryption strength: LIGHT, STANDARD, HEAVY, SUPER_HEAVY",
            defaultValue = "STANDARD")
    private String stringStrength;

    @Option(names = {"--no-rename-classes"}, description = "Disable class renaming")
    private boolean noRenameClasses;

    @Option(names = {"--no-rename-methods"}, description = "Disable method renaming")
    private boolean noRenameMethods;

    @Option(names = {"--no-rename-fields"}, description = "Disable field renaming")
    private boolean noRenameFields;

    @Option(names = {"--no-strings"}, description = "Disable string encryption")
    private boolean noStrings;

    @Option(names = {"--no-numbers"}, description = "Disable number obfuscation")
    private boolean noNumbers;

    @Option(names = {"--analyze-only"}, description = "Only analyze, don't transform")
    private boolean analyzeOnly;

    @Option(names = {"--dry-run"}, description = "Show what would be renamed without applying")
    private boolean dryRun;

    @Option(names = {"-v", "--verbose"}, description = "Verbose output")
    private boolean verbose;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        System.out.println("=== Java Bytecode Obfuscator v1.0.0 ===");
        
        if (verbose) {
            System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, "DEBUG");
        }

        Obfuscator.Config config = new Obfuscator.Config();
        config.namingStrategy = parseStrategy(strategy);
        config.stringStrength = parseStringStrength(stringStrength);
        config.renameClasses = !noRenameClasses;
        config.renameMethods = !noRenameMethods;
        config.renameFields = !noRenameFields;
        config.enableStringEncryption = !noStrings;
        config.enableNumberObfuscation = !noNumbers;

        Obfuscator obfuscator = new Obfuscator(config);

        // Load input
        System.out.println("Loading input JAR: " + input);
        obfuscator.loadInput(input);

        // Load libraries
        if (!libraries.isEmpty()) {
            System.out.println("Loading " + libraries.size() + " library JARs...");
            obfuscator.loadLibraries(libraries);
        }

        // Detect compatibility profile
        obfuscator.detectCompat();

        // Analyze
        obfuscator.analyze();

        if (analyzeOnly || dryRun) {
            MappingTable mt = obfuscator.getMappingTable();
            System.out.println("\nAnalysis complete:");
            System.out.println("  Classes: " + mt.getClassCount() + " would be renamed");
            System.out.println("  Methods: " + mt.getMethodCount() + " would be renamed");
            System.out.println("  Fields: " + mt.getFieldCount() + " would be renamed");
            return 0;
        }

        // Transform
        obfuscator.transform();

        // Verify
        obfuscator.verify();

        // Write output
        System.out.println("Writing output JAR: " + output);
        obfuscator.writeOutput(output);

        // Save mapping
        if (mapping != null) {
            obfuscator.saveMapping(mapping);
            System.out.println("Mapping saved to: " + mapping);
        }

        System.out.println("\n=== Obfuscation complete ===");
        return 0;
    }

    private core.transformers.phase1.RenamerTransformer.NamingStrategy parseStrategy(String s) {
        try {
            return core.transformers.phase1.RenamerTransformer.NamingStrategy.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.err.println("Unknown strategy: " + s + ", using ALPHABET");
            return core.transformers.phase1.RenamerTransformer.NamingStrategy.ALPHABET;
        }
    }

    private core.transformers.phase2.StringEncryptionTransformer.Strength parseStringStrength(String s) {
        try {
            return core.transformers.phase2.StringEncryptionTransformer.Strength.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.err.println("Unknown strength: " + s + ", using STANDARD");
            return core.transformers.phase2.StringEncryptionTransformer.Strength.STANDARD;
        }
    }
}
