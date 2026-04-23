package dev.kurumi.obfuscator.core;

import dev.kurumi.obfuscator.config.ExemptionResolver;
import dev.kurumi.obfuscator.config.ObfuscatorConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Top-level orchestrator: load the input JAR, run the pipeline, write the
 * output JAR, and optionally persist the rename mapping for stack-trace
 * retrace.
 */
public class Obfuscator {

    private static final Logger log = LoggerFactory.getLogger(Obfuscator.class);

    private final ObfuscatorConfig config;

    public Obfuscator(ObfuscatorConfig config) {
        this.config = config;
    }

    public ObfuscationResult run() throws IOException {
        ClassPool pool = new ClassPool();

        Path input = config.input();
        log.info("Loading input JAR: {}", input);
        pool.loadJar(input);
        log.info("Loaded {} classes, {} resources", pool.size(), pool.resources().size());

        for (Path lib : config.libraries()) {
            log.info("Loading library: {}", lib);
            pool.loadLibrary(lib);
        }

        ExemptionResolver exemptions = new ExemptionResolver(config);
        ObfuscatorContext ctx = new ObfuscatorContext(config, exemptions);

        TransformerPipeline pipeline = new TransformerPipeline(config);
        pipeline.execute(pool, ctx);

        if (!config.dryRun()) {
            Path output = config.output();
            log.info("Writing output JAR: {}", output);
            new JarWriter(pool).write(output);
        } else {
            log.info("Dry-run complete (no JAR written).");
        }

        if (config.saveMapping() != null) {
            writeMapping(ctx, config.saveMapping());
        }

        return new ObfuscationResult(pool.size(), ctx);
    }

    private void writeMapping(ObfuscatorContext ctx, Path path) throws IOException {
        StringBuilder sb = new StringBuilder();
        Map<String, String> classMap = ctx.classMapping();
        Map<String, String> methodMap = ctx.methodMapping();
        Map<String, String> fieldMap = ctx.fieldMapping();

        Map<String, Map<String, String>> methodsByOwner = new LinkedHashMap<>();
        Map<String, Map<String, String>> fieldsByOwner = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : methodMap.entrySet()) {
            String key = e.getKey();
            int dot = key.indexOf('.');
            String owner = key.substring(0, dot);
            methodsByOwner.computeIfAbsent(owner, k -> new LinkedHashMap<>())
                    .put(key.substring(dot + 1), e.getValue());
        }
        for (Map.Entry<String, String> e : fieldMap.entrySet()) {
            String key = e.getKey();
            int dot = key.indexOf('.');
            String owner = key.substring(0, dot);
            fieldsByOwner.computeIfAbsent(owner, k -> new LinkedHashMap<>())
                    .put(key.substring(dot + 1), e.getValue());
        }

        for (Map.Entry<String, String> e : classMap.entrySet()) {
            sb.append(e.getKey()).append(" -> ").append(e.getValue()).append('\n');
            Map<String, String> methods = methodsByOwner.get(e.getKey());
            if (methods != null) {
                for (Map.Entry<String, String> m : methods.entrySet()) {
                    sb.append("    ").append(m.getKey()).append(" -> ").append(m.getValue()).append('\n');
                }
            }
            Map<String, String> fields = fieldsByOwner.get(e.getKey());
            if (fields != null) {
                for (Map.Entry<String, String> f : fields.entrySet()) {
                    sb.append("    #").append(f.getKey()).append(" -> ").append(f.getValue()).append('\n');
                }
            }
        }
        // include mappings for classes that were not renamed themselves
        for (String owner : methodsByOwner.keySet()) {
            if (classMap.containsKey(owner)) continue;
            sb.append(owner).append(" -> ").append(owner).append('\n');
            for (Map.Entry<String, String> m : methodsByOwner.get(owner).entrySet()) {
                sb.append("    ").append(m.getKey()).append(" -> ").append(m.getValue()).append('\n');
            }
        }

        Files.writeString(path, sb.toString());
        log.info("Wrote mapping file: {}", path);
    }

    public static final class ObfuscationResult {
        private final int classCount;
        private final ObfuscatorContext context;

        ObfuscationResult(int classCount, ObfuscatorContext context) {
            this.classCount = classCount;
            this.context = context;
        }

        public int classCount() {
            return classCount;
        }

        public ObfuscatorContext context() {
            return context;
        }
    }
}
