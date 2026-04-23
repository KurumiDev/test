package obfuscator.core;

import obfuscator.analysis.*;
import obfuscator.compat.*;
import obfuscator.transformers.phase1.LocalVariableTransformer;
import obfuscator.transformers.phase1.RenamerTransformer;
import obfuscator.transformers.phase2.NumberObfuscationTransformer;
import obfuscator.transformers.phase2.StringEncryptionTransformer;
import obfuscator.transformers.phase3.FlowObfuscationTransformer;
import obfuscator.transformers.phase3.OpaquePredicateTransformer;
import obfuscator.transformers.phase3.InvokeDynamicTransformer;
import org.objectweb.asm.tree.ClassNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Main obfuscator orchestrator.
 */
public class Obfuscator {
    private static final Logger LOG = LoggerFactory.getLogger(Obfuscator.class);

    private final ClassPool pool;
    private final InheritanceGraph inheritanceGraph;
    private final AnnotationScanner annotationScanner;
    private final ExemptionResolver exemptionResolver;
    private CompatProfile compatProfile;

    // Configuration
    private final RenamerTransformer.NamingStrategy namingStrategy;
    private final StringEncryptionTransformer.Strength stringStrength;
    private final boolean renameClasses;
    private final boolean renameMethods;
    private final boolean renameFields;
    private final boolean enableStringEncryption;
    private final boolean enableNumberObfuscation;
    private final boolean enableFlowObfuscation;
    private final boolean enableOpaquePredicates;
    private final boolean enableInvokeDynamic;
    private final FlowObfuscationTransformer.Technique flowTechnique;
    private final Set<OpaquePredicateTransformer.Category> predicateCategories;
    private final double predicateDensity;

    public Obfuscator(Config config) {
        this.pool = new ClassPool();
        this.inheritanceGraph = new InheritanceGraph();
        this.annotationScanner = new AnnotationScanner();
        this.exemptionResolver = new ExemptionResolver(annotationScanner, inheritanceGraph);
        
        this.namingStrategy = config.namingStrategy;
        this.stringStrength = config.stringStrength;
        this.renameClasses = config.renameClasses;
        this.renameMethods = config.renameMethods;
        this.renameFields = config.renameFields;
        this.enableStringEncryption = config.enableStringEncryption;
        this.enableNumberObfuscation = config.enableNumberObfuscation;
        this.enableFlowObfuscation = config.enableFlowObfuscation;
        this.enableOpaquePredicates = config.enableOpaquePredicates;
        this.enableInvokeDynamic = config.enableInvokeDynamic;
        this.flowTechnique = config.flowTechnique;
        this.predicateCategories = config.predicateCategories;
        this.predicateDensity = config.predicateDensity;
    }

    public void loadInput(Path inputJar) throws IOException {
        pool.loadJar(inputJar);
    }

    public void loadLibraries(List<Path> libraries) throws IOException {
        for (Path lib : libraries) {
            pool.loadLibrary(lib);
        }
    }

    public void detectCompat() {
        compatProfile = detectProfile();
        LOG.info("Detected compatibility profile: {}", 
                compatProfile != null ? compatProfile.getClass().getSimpleName() : "Plain");
        
        if (compatProfile != null) {
            // Apply compatibility exemptions
            for (String iface : compatProfile.getExemptInterfaces()) {
                LOG.debug("Adding exempt interface: {}", iface);
            }
        }
    }

    private CompatProfile detectProfile() {
        if (pool.hasClass("org/bukkit/plugin/java/JavaPlugin")) {
            return new PaperCompat();
        }
        if (pool.hasClass("net/md_5/bungee/api/plugin/Plugin")) {
            return new BungeeCompat();
        }
        if (pool.hasClass("com/velocitypowered/api/plugin/Plugin")) {
            return new VelocityCompat();
        }
        if (pool.hasClass("net/fabricmc/api/ModInitializer")) {
            return new FabricCompat();
        }
        if (pool.hasClass("net/minecraftforge/fml/common/Mod")) {
            return new ForgeCompat();
        }
        return null;
    }

    public void analyze() {
        LOG.info("=== PHASE 1: ANALYSIS ===");
        
        // Build inheritance graph
        inheritanceGraph.build(pool);
        
        // Scan annotations
        annotationScanner.scan(pool);
        
        // Resolve exemptions
        exemptionResolver.resolve(pool);
        
        // Detect lambdas
        var classesWithLambdas = LambdaDetector.scanClasses(pool.getOwnClasses());
        
        LOG.info("Analysis complete");
    }

    public void transform() {
        LOG.info("=== PHASE 2: TRANSFORMATION ===");
        
        // Phase 1: Safe transformations
        LOG.info("--- Phase 1: Safe transformations ---");
        
        RenamerTransformer renamer = new RenamerTransformer(
            pool, pool.getMappingTable(), exemptionResolver,
            namingStrategy, renameClasses, renameMethods, renameFields, true
        );
        renamer.transform();
        
        LocalVariableTransformer localRenamer = new LocalVariableTransformer(pool);
        localRenamer.transform();
        
        // Phase 2: Medium transformations
        LOG.info("--- Phase 2: Medium transformations ---");
        
        if (enableNumberObfuscation) {
            NumberObfuscationTransformer numberObf = new NumberObfuscationTransformer(
                pool, 10, true, true
            );
            numberObf.transform();
        }
        
        if (enableStringEncryption) {
            StringEncryptionTransformer stringEnc = new StringEncryptionTransformer(
                pool, stringStrength, true, false
            );
            stringEnc.transform();
        }
        
        // Phase 3: Aggressive transformations
        LOG.info("--- Phase 3: Aggressive transformations ---");
        
        if (enableFlowObfuscation) {
            FlowObfuscationTransformer flowObf = new FlowObfuscationTransformer(
                pool, flowTechnique, FlowObfuscationTransformer.Complexity.MEDIUM, true
            );
            flowObf.transform();
        }
        
        if (enableOpaquePredicates) {
            OpaquePredicateTransformer opaqueObf = new OpaquePredicateTransformer(
                pool, predicateCategories, predicateDensity
            );
            opaqueObf.transform();
        }
        
        if (enableInvokeDynamic) {
            InvokeDynamicTransformer invokeDyn = new InvokeDynamicTransformer(
                pool, true
            );
            invokeDyn.transform();
        }
        
        LOG.info("Transformation complete");
    }

    public void verify() {
        LOG.info("=== PHASE 4: VERIFICATION ===");
        
        int errors = 0;
        for (ClassNode cn : pool.getOwnClasses()) {
            try {
                byte[] bytes = pool.writeClass(cn);
                // Try to load in isolated ClassLoader
                testLoad(cn.name, bytes);
            } catch (Exception e) {
                LOG.error("Verification failed for {}: {}", cn.name, e.getMessage());
                errors++;
            }
        }
        
        if (errors > 0) {
            LOG.warn("Verification completed with {} errors", errors);
        } else {
            LOG.info("Verification passed for all classes");
        }
    }

    private void testLoad(String className, byte[] bytes) {
        try {
            ClassLoader cl = new ClassLoader(null) {
                protected Class<?> findClass(String name) {
                    return defineClass(name.replace('/', '.'), bytes, 0, bytes.length);
                }
            };
            cl.loadClass(className.replace('/', '.'));
        } catch (VerifyError | ClassFormatError e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            // Other exceptions are OK
        }
    }

    public void writeOutput(Path outputJar) throws IOException {
        LOG.info("=== PHASE 5: WRITE OUTPUT ===");
        JarWriter.write(outputJar, pool, true);
    }

    public void saveMapping(Path mappingPath) throws IOException {
        if (mappingPath != null) {
            pool.getMappingTable().save(mappingPath);
        }
    }

    public MappingTable getMappingTable() {
        return pool.getMappingTable();
    }

    public static class Config {
        public RenamerTransformer.NamingStrategy namingStrategy = RenamerTransformer.NamingStrategy.ALPHABET;
        public StringEncryptionTransformer.Strength stringStrength = StringEncryptionTransformer.Strength.STANDARD;
        public boolean renameClasses = true;
        public boolean renameMethods = true;
        public boolean renameFields = true;
        public boolean enableStringEncryption = true;
        public boolean enableNumberObfuscation = true;
        public boolean enableFlowObfuscation = true;
        public boolean enableOpaquePredicates = true;
        public boolean enableInvokeDynamic = true;
        public FlowObfuscationTransformer.Technique flowTechnique = FlowObfuscationTransformer.Technique.ALL;
        public Set<OpaquePredicateTransformer.Category> predicateCategories = Set.of(
            OpaquePredicateTransformer.Category.ALIASING,
            OpaquePredicateTransformer.Category.RUNTIME_STATE,
            OpaquePredicateTransformer.Category.CROSS_METHOD
        );
        public double predicateDensity = 0.3;
    }
}
