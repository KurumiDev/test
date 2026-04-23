# Java Bytecode Obfuscator

Production-grade Java bytecode obfuscator written on top of ASM 9.7. Designed
for Minecraft Paper / Spigot / Bungee / Velocity plugins and Fabric / Forge
mods, but works on arbitrary JARs.

## Features

- **Renamer** — class / method / field / local variable renaming with
  inheritance-aware equivalence-class analysis. Preserves virtual dispatch,
  respects `@EventHandler`, `@Subscribe`, `@SerializedName`, mixin annotations
  and platform supertypes (`JavaPlugin`, `Listener`, `ModInitializer`, …).
- **String encryption** — per-class (STANDARD) or per-class+per-method (HEAVY)
  XOR-stream cipher backed by an injected, synthetic `$obfD` method.
- **Flow obfuscation** — bogus jumps, goto-spaghetti, and bogus exception
  guards driven by opaque predicates.
- **Opaque predicates** — math, runtime, and mixed strategies.
- **Number obfuscation** — replaces magic numbers with XOR / add-sub / bit-flip
  identities.
- **InvokeDynamic** — converts plain `invokestatic` calls through a custom
  bootstrap method; auto-disabled when the input contains lambdas.
- **Compat providers** — Paper, Bungee, Velocity, Fabric, Forge exemptions out
  of the box; target auto-detected from `plugin.yml`, `fabric.mod.json`,
  `mods.toml`, `velocity-plugin.json`, or class imports.
- **Bytecode verifier** — every pass can be followed by a pool-wide
  `CheckClassAdapter` pass.
- **Retrace tool** — `obfuscator retrace` reverses obfuscated stack traces
  using the emitted mapping file.

## Build

```bash
mvn -B package
```

Produces a fat executable JAR at `target/obfuscator.jar`.

## Usage

```bash
# Minimal
java -jar target/obfuscator.jar --input plugin.jar --output plugin-obf.jar

# With a config file
java -jar target/obfuscator.jar --config obfuscator.hocon

# Auto-detect target and save a mapping file
java -jar target/obfuscator.jar --input plugin.jar --output plugin-obf.jar \
    --auto --save-mapping mapping.txt

# Dry run — analyse only, no output
java -jar target/obfuscator.jar --input plugin.jar --dry-run

# Retrace an obfuscated stack trace
java -jar target/obfuscator.jar retrace --mapping mapping.txt --trace error.log
```

See `obfuscator.example.hocon` for the full configuration reference.

## Architecture

```
core/        — Obfuscator, ClassPool, JarWriter, TransformerPipeline
transformers/ — Renamer, StringEncryption, Flow, Number, Opaque, InvokeDyn, ...
analysis/    — DependencyAnalyzer, InheritanceAnalyzer, AnnotationScanner
config/      — ObfuscatorConfig (HOCON), RuleEngine, ExemptionResolver
compat/      — PaperPluginCompat, BungeeCompat, VelocityCompat, FabricCompat, ForgeCompat
verify/      — BytecodeVerifier (CheckClassAdapter wrapper)
retrace/     — RetraceTool
cli/         — Main (picocli)
```

## Pipeline order

Analyses run first, then transforms in an order chosen to minimise
post-transform breakage:

1. `dependency-analyzer` — detect target, activate compat providers
2. `inheritance-analyzer` — build ancestor maps
3. `annotation-scanner` — collect annotation-based exemptions
4. `renamer`
5. `number-obfuscation`
6. `string-encryption`
7. `bogus-exception`
8. `flow-obfuscation`
9. `opaque-predicates`
10. `invokedynamic` (only if no lambdas detected)
11. `local-variable` (debug metadata strip)
