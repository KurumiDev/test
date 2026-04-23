package com.obfuscator.cli;

import com.obfuscator.config.ObfuscatorConfig;
import com.obfuscator.core.ClassPool;
import com.obfuscator.core.JarWriter;
import com.obfuscator.core.TransformerPipeline;
import picocli.CommandLine;
import picocli.CommandLine.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
    name = "obfuscator",
    mixinStandardHelpOptions = true,
    version = "Bytecode Obfuscator 1.0.0",
    description = "Production-ready Java bytecode obfuscator for Minecraft plugins"
)
public class Main implements Callable<Integer> {

    @Option(names = {"-i", "--input"}, required = true, description = "Input JAR file")
    private File input;

    @Option(names = {"-o", "--output"}, required = true, description = "Output JAR file")
    private File output;

    @Option(names = {"-c", "--config"}, description = "Configuration file (HOCON)")
    private File config;

    @Option(names = {"--auto"}, description = "Auto-detect project type and apply appropriate exemptions")
    private boolean autoDetect;

    @Option(names = {"-v", "--verbose"}, description = "Verbose output")
    private boolean verbose;

    @Option(names = {"--dry-run"}, description = "Analyze without writing output")
    private boolean dryRun;

    @Option(names = {"--show-mapping"}, description = "Show renaming mapping without applying")
    private boolean showMapping;

    @Option(names = {"--save-mapping"}, description = "Save mapping to file for stack trace retrace")
    private File saveMapping;

    @Option(names = {"--target"}, description = "Target platform: auto, paper, fabric, forge, bungee, velocity, plain")
    private String target = "auto";

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║     BYTECODE OBFUSCATOR v1.0.0 - Production Ready        ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println();

        // Load configuration
        ObfuscatorConfig cfg;
        if (config != null && config.exists()) {
            cfg = ObfuscatorConfig.load(config.toPath());
            System.out.println("[+] Loaded configuration: " + config.getAbsolutePath());
        } else {
            cfg = ObfuscatorConfig.defaultConfig();
            System.out.println("[+] Using default configuration");
        }

        // Override with CLI options
        if (target != null && !target.equals("auto")) {
            cfg.setTarget(target);
        }

        Path inputPath = input.toPath();
        Path outputPath = output.toPath();

        if (!Files.exists(inputPath)) {
            System.err.println("[ERROR] Input file not found: " + inputPath);
            return 1;
        }

        // Initialize ClassPool
        ClassPool pool = new ClassPool();
        
        System.out.println("[+] Loading input JAR: " + inputPath.getFileName());
        pool.loadJar(inputPath);
        System.out.println("    Classes loaded: " + pool.getClassCount());
        System.out.println("    Resources loaded: " + pool.getResourceCount());

        // Auto-detect platform
        if (autoDetect || "auto".equals(cfg.getTarget())) {
            String detected = pool.detectPlatform();
            cfg.setTarget(detected);
            System.out.println("[+] Auto-detected platform: " + detected);
        }

        // Load libraries for analysis
        for (String lib : cfg.getLibrariesAsString()) {
            Path libPath = Path.of(lib);
            if (Files.exists(libPath)) {
                pool.loadLibrary(libPath);
                System.out.println("[+] Loaded library: " + lib);
            }
        }

        // Create pipeline
        TransformerPipeline pipeline = new TransformerPipeline(pool, cfg);

        // Dry run or show mapping
        if (dryRun) {
            System.out.println("\n[DRY RUN] Analysis complete, no changes written");
            pipeline.printAnalysisSummary();
            return 0;
        }

        if (showMapping) {
            pipeline.printRenamingMapping();
            return 0;
        }

        // Execute transformation pipeline
        System.out.println("\n[+] Starting transformation pipeline...");
        pipeline.execute();

        // Save mapping if requested
        if (saveMapping != null) {
            try (FileWriter writer = new FileWriter(saveMapping)) {
                writer.write(pipeline.getMappingAsString());
                System.out.println("[+] Mapping saved to: " + saveMapping.getAbsolutePath());
            }
        }

        // Write output JAR
        if (!dryRun) {
            JarWriter writer = new JarWriter(pool);
            writer.write(outputPath);
            System.out.println("\n[+] Output JAR written: " + outputPath.getFileName());
            
            long originalSize = Files.size(inputPath);
            long obfuscatedSize = Files.size(outputPath);
            System.out.printf("    Original size: %,d bytes%n", originalSize);
            System.out.printf("    Obfuscated size: %,d bytes%n", obfuscatedSize);
            System.out.printf("    Size change: %+.1f%%%n", 
                (obfuscatedSize - (double) originalSize) / originalSize * 100);
        }

        System.out.println("\n[+] Obfuscation complete!");
        return 0;
    }
}
