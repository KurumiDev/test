package dev.kurumi.obfuscator.cli;

import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import dev.kurumi.obfuscator.core.Obfuscator;
import dev.kurumi.obfuscator.retrace.RetraceTool;
import dev.kurumi.obfuscator.transformers.WatermarkTransformer;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "obfuscator",
        mixinStandardHelpOptions = true,
        version = "0.1.0",
        description = "Production-ready Java bytecode obfuscator",
        subcommands = {Main.RetraceSubcommand.class, Main.RetraceWatermarkSubcommand.class})
public class Main implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    @Option(names = {"-i", "--input"}, description = "Input JAR file")
    Path input;

    @Option(names = {"-o", "--output"}, description = "Output JAR file")
    Path output;

    @Option(names = {"-c", "--config"}, description = "HOCON config file")
    Path configPath;

    @Option(names = {"--library"}, description = "Additional library JAR(s) for inheritance analysis")
    List<Path> libraries = new ArrayList<>();

    @Option(names = {"--auto"}, description = "Auto-detect target (paper/fabric/forge/...)")
    boolean auto;

    @Option(names = {"-v", "--verbose"}, description = "Verbose logging")
    boolean verbose;

    @Option(names = {"--dry-run"}, description = "Analyze only, do not write output")
    boolean dryRun;

    @Option(names = {"--show-mapping"}, description = "Print mappings to stdout on completion")
    boolean showMapping;

    @Option(names = {"--save-mapping"}, description = "Write the rename mapping to this file")
    Path saveMapping;

    @Option(names = {"--strategy"}, description = "Naming strategy: ALPHABET|UNICODE|CONFUSE|RANDOM_HEX")
    ObfuscatorConfig.NamingStrategy strategy;

    @Option(names = {"--strength"}, description = "String encryption strength: LIGHT|STANDARD|HEAVY")
    ObfuscatorConfig.StringStrength strength;

    @Override
    public Integer call() {
        if (verbose) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        }

        ObfuscatorConfig.Builder b = configPath != null
                ? fromConfigBuilder(configPath)
                : new ObfuscatorConfig.Builder();

        if (input != null) b.input = input;
        if (output != null) b.output = output;
        if (!libraries.isEmpty()) b.libraries.addAll(libraries);
        if (auto) b.target = ObfuscatorConfig.Target.AUTO;
        if (dryRun) b.dryRun = true;
        if (saveMapping != null) b.saveMapping = saveMapping;
        if (strategy != null) b.namingStrategy = strategy;
        if (strength != null) b.stringStrength = strength;

        if (b.input == null) {
            log.error("--input or a config with 'input' is required");
            return 2;
        }
        if (b.output == null && !b.dryRun) {
            log.error("--output is required unless --dry-run");
            return 2;
        }

        ObfuscatorConfig cfg = b.build();

        try {
            Obfuscator.ObfuscationResult res = new Obfuscator(cfg).run();
            log.info("Done: {} classes processed", res.classCount());
            if (showMapping) {
                res.context().classMapping().forEach((k, v) -> System.out.println(k + " -> " + v));
                res.context().methodMapping().forEach((k, v) -> System.out.println(k + " -> " + v));
                res.context().fieldMapping().forEach((k, v) -> System.out.println(k + " -> " + v));
            }
            return 0;
        } catch (Exception ex) {
            log.error("Obfuscation failed", ex);
            return 1;
        }
    }

    private static ObfuscatorConfig.Builder fromConfigBuilder(Path path) {
        ObfuscatorConfig loaded = ObfuscatorConfig.fromFile(path);
        ObfuscatorConfig.Builder b = new ObfuscatorConfig.Builder();
        b.input = loaded.input();
        b.output = loaded.output();
        b.libraries.addAll(loaded.libraries());
        b.target = loaded.target();
        b.namingStrategy = loaded.namingStrategy();
        b.renameClasses = loaded.renameClasses();
        b.renameMethods = loaded.renameMethods();
        b.renameFields = loaded.renameFields();
        b.renameLocalVars = loaded.renameLocalVars();
        b.stringStrength = loaded.stringStrength();
        b.flowTechnique = loaded.flowTechnique();
        b.flowComplexity = loaded.flowComplexity();
        b.opaqueType = loaded.opaqueType();
        b.numberOnlyMagic = loaded.numberOnlyMagic();
        b.invokeDynamicAutoDetectLambdas = loaded.invokeDynamicAutoDetectLambdas();
        b.exemptions = new ArrayList<>(loaded.exemptions());
        b.autoExempt = loaded.autoExempt();
        b.dryRun = loaded.dryRun();
        b.saveMapping = loaded.saveMapping();
        b.verifyAfterEach = loaded.verifyAfterEach();
        b.failOnVerifyError = loaded.failOnVerifyError();
        // transformer-enabled flags
        b.renamerEnabled = loaded.isTransformerEnabled("renamer");
        b.stringEncryptionEnabled = loaded.isTransformerEnabled("string-encryption");
        b.flowEnabled = loaded.isTransformerEnabled("flow-obfuscation");
        b.bogusExceptionEnabled = loaded.isTransformerEnabled("bogus-exception");
        b.opaqueEnabled = loaded.isTransformerEnabled("opaque-predicates");
        b.numberEnabled = loaded.isTransformerEnabled("number-obfuscation");
        b.invokeDynamicEnabled = loaded.isTransformerEnabled("invokedynamic");
        b.classLiteralEnabled = loaded.isTransformerEnabled("class-literal");
        b.stringConcatEnabled = loaded.isTransformerEnabled("string-concat");
        b.indyCallEnabled = loaded.isTransformerEnabled("indy-call");
        b.junkCodeEnabled = loaded.isTransformerEnabled("junk-code");
        b.accessFlagsEnabled = loaded.isTransformerEnabled("access-flags");
        b.memberShufflerEnabled = loaded.isTransformerEnabled("member-shuffler");
        b.sourceScrubEnabled = loaded.isTransformerEnabled("source-scrub");
        b.blobStringEnabled = loaded.isTransformerEnabled("blob-string");
        b.localVarTableEnabled = loaded.isTransformerEnabled("local-variable-table");
        b.localVarEnabled = loaded.isTransformerEnabled("local-variable");
        b.classExplodeEnabled = loaded.isTransformerEnabled("class-explode");
        b.indyFieldEnabled = loaded.isTransformerEnabled("indy-field");
        b.encryptedClassVaultEnabled = loaded.isTransformerEnabled("encrypted-class-vault");
        b.cfgFlattenEnabled = loaded.isTransformerEnabled("cfg-flatten");
        b.fakeAnnotationsEnabled = loaded.isTransformerEnabled("fake-annotations");
        b.antiAgentEnabled = loaded.isTransformerEnabled("anti-agent");
        b.watermarkEnabled = loaded.isTransformerEnabled("watermark");
        return b;
    }

    public static void main(String[] args) {
        int code = new CommandLine(new Main()).execute(args);
        System.exit(code);
    }

    @Command(name = "retrace-watermark", description = "Decode the per-build watermark stamped into an obfuscated JAR")
    public static class RetraceWatermarkSubcommand implements Callable<Integer> {

        @Option(names = {"--jar"}, required = true, description = "Obfuscated JAR file to inspect")
        Path jar;

        @Override
        public Integer call() throws Exception {
            String found = null;
            try (java.util.jar.JarFile jf = new java.util.jar.JarFile(jar.toFile())) {
                java.util.Enumeration<java.util.jar.JarEntry> entries = jf.entries();
                while (entries.hasMoreElements() && found == null) {
                    java.util.jar.JarEntry je = entries.nextElement();
                    if (!je.getName().endsWith(".class")) continue;
                    byte[] bytes;
                    try (java.io.InputStream in = jf.getInputStream(je)) {
                        bytes = in.readAllBytes();
                    }
                    ClassNode cn = new ClassNode();
                    new ClassReader(bytes).accept(cn, ClassReader.SKIP_CODE);
                    if (cn.fields == null) continue;
                    for (FieldNode fn : cn.fields) {
                        if (fn.name.contains("wm_") && fn.value instanceof String s
                                && s.startsWith("WM1$")) {
                            String decoded = WatermarkTransformer.decodeWatermark(fn.name, s);
                            if (decoded != null) {
                                found = decoded;
                                break;
                            }
                        }
                    }
                }
            }
            if (found == null) {
                System.err.println("No watermark found in " + jar);
                return 1;
            }
            System.out.println(found);
            return 0;
        }
    }

    @Command(name = "retrace", description = "De-obfuscate a stack trace using a mapping file")
    public static class RetraceSubcommand implements Callable<Integer> {

        @Option(names = {"--mapping"}, required = true, description = "Mapping file produced by --save-mapping")
        Path mapping;

        @Option(names = {"--trace"}, description = "Input stack trace file (defaults to stdin)")
        Path trace;

        @Override
        public Integer call() throws Exception {
            RetraceTool tool = new RetraceTool(mapping);
            String input;
            if (trace != null) {
                input = java.nio.file.Files.readString(trace);
            } else {
                input = new String(System.in.readAllBytes());
            }
            String out = tool.retrace(input);
            System.out.println(out);
            return 0;
        }
    }
}
