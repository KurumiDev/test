<div align="center">

# 🔒 Kurumi Obfuscator

**Production-grade Java bytecode obfuscator. ASM 9.7. 16 transformers. Zelix-class output.**

[![CI](https://github.com/KurumiDev/test/actions/workflows/ci.yml/badge.svg)](https://github.com/KurumiDev/test/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/KurumiDev/test?include_prereleases&label=release)](https://github.com/KurumiDev/test/releases)
[![Java](https://img.shields.io/badge/java-17%2B-orange.svg)](https://adoptium.net/)
[![ASM](https://img.shields.io/badge/asm-9.7-red.svg)](https://asm.ow2.io/)

Designed for Minecraft **Paper / Spigot / Bungee / Velocity** plugins and
**Fabric / Forge** mods, but works on any JAR.

[Quick start](#quick-start) · [Transformers](#transformers) · [Config](#configuration) · [Presets](#presets) · [Benchmarks](#benchmarks) · [Retrace](#retrace)

</div>

---

## Quick start

```bash
git clone https://github.com/KurumiDev/test.git
cd test && mvn -B package
java -jar target/obfuscator.jar --input plugin.jar --output plugin-obf.jar
```

Or grab the shaded JAR from the [latest release](https://github.com/KurumiDev/test/releases/latest):

```bash
wget https://github.com/KurumiDev/test/releases/latest/download/obfuscator.jar
java -jar obfuscator.jar --input plugin.jar --output plugin-obf.jar --save-mapping mapping.txt
```

---

## Transformers

| # | Transformer | What it does | Breaks |
|---|-------------|--------------|--------|
| 1 | **renamer** | Class/method/field/local renaming with inheritance-aware union-find over virtual dispatch groups. Respects `@EventHandler`, `@Subscribe`, `@SerializedName`, mixins, and JDK/platform supertypes. | identifier-based analysis, reflection by name |
| 2 | **number-obfuscation** | Replaces magic numeric constants with XOR / bit-flip identities. | literal-scan for crypto constants, keys |
| 3 | **class-literal** | Rewrites `Foo.class` into `Class.forName(decrypt(…))` using the encrypted string table. | type tracking, reflection-by-constant |
| 4 | **string-concat** | Expands JDK 9+ `makeConcatWithConstants` into explicit `StringBuilder` chains so recipe literals become LDC strings for downstream encryption. | static string recovery from BSM args |
| 5 | **blob-string** *(opt-in)* | Packs every LDC string in a class into a single encrypted `byte[]` with position-dependent key schedule; lookups go through a lazy per-class decoder. | grep / Base64 scanning, per-string attack |
| 6 | **string-encryption** | HEAVY XOR stream: `classKey ⊕ methodKey ⊕ perCallSalt`. Each call site has a unique salt. | decryption-by-replay, static XOR crack |
| 7 | **bogus-exception** | Wraps methods in unreachable `try/catch` blocks with opaque predicates guarding the real path. | control-flow reconstruction |
| 8 | **flow-obfuscation** | Bogus jumps, *real* GOTO-spaghetti (block rotation), exception-based flow — combined via `ALL` technique. | CFR / Fernflower / Procyon structured output |
| 9 | **opaque-predicates** | Runtime-seeded predicates (`System.nanoTime() \| 1`, `availableProcessors() \| 1`, `currentTimeMillis() << 1`) re-evaluated each class load. Static constant-folding **cannot** prove them. | static dead-branch elimination, symbolic exec |
| 10 | **invokedynamic** | Wraps `INVOKESTATIC` calls in `invokedynamic` with a custom bootstrap, auto-disabled on lambdas. | decompiler call-site reconstruction |
| 11 | **indy-call** *(opt-in)* | Wraps cross-pool `INVOKESTATIC / VIRTUAL / INTERFACE` in `invokedynamic` with a BSM that resolves encrypted owner/name/descriptor via `MethodHandles.Lookup` at link time. | ALL decompilers (no bootstrap recovery) |
| 12 | **junk-code** | Injects realistic-looking dead `synthetic` methods — reverse-engineering honeypots. | time wasted on decoy code paths |
| 13 | **access-flags** | Marks user methods/fields `ACC_SYNTHETIC` so IDE autocomplete hides them. | IDE-assisted reading |
| 14 | **member-shuffler** | Randomizes method/field order within each class. | `diff`-based analysis, stable hashes |
| 15 | **source-scrub** | Strips `SourceFile` and `SourceDebugExtension`, replaces with plausible decoys (`main.java`, `Gen.java`). | source-aware decompilers |
| 16 | **local-variable** + **local-variable-table** | Strips real debug LVT, injects a synthetic one with Java reserved keywords (`int`, `class`, `null`), zero-width chars, and confusables — IDE shows uncompilable garbage. | IDE reading of decompiled source |

All passes are re-orderable but the **default pipeline** is analysis →
rename → numbers → class-literals → concat → blob/strings → flow passes →
invokedynamic → cosmetic. Every pass can optionally be followed by a
pool-wide `CheckClassAdapter` pass (`verify-after-each: true`).

---

## Presets

Drop one of these into `transformers.hocon`:

<details>
<summary><b>LIGHT</b> — renaming + basic string encryption. ~+10% size.</summary>

```hocon
transformers {
    renamer { enabled = true, strategy = ALPHABET }
    string-encryption { enabled = true, strength = LIGHT }
    flow-obfuscation { enabled = false }
    opaque-predicates { enabled = false }
    number-obfuscation { enabled = false }
    class-literal { enabled = false }
    string-concat { enabled = false }
    blob-string { enabled = false }
    indy-call { enabled = false }
    junk-code { enabled = false }
    bogus-exception { enabled = false }
    access-flags { enabled = false }
    member-shuffler { enabled = false }
    source-scrub { enabled = true }
    local-variable { enabled = true }
    local-variable-table { enabled = false }
}
```
</details>

<details>
<summary><b>STANDARD</b> — default. Renaming + HEAVY strings + flow + opaque. ~+30% size, survives all known decompilers.</summary>

```hocon
transformers {
    renamer { enabled = true, strategy = ALPHABET }
    string-encryption { enabled = true, strength = HEAVY }
    string-concat { enabled = true }
    class-literal { enabled = true }
    number-obfuscation { enabled = true }
    bogus-exception { enabled = true }
    flow-obfuscation { enabled = true, technique = ALL, complexity = 2 }
    opaque-predicates { enabled = true, type = MIXED }
    junk-code { enabled = true }
    access-flags { enabled = true }
    member-shuffler { enabled = true }
    source-scrub { enabled = true }
    local-variable { enabled = true }
    local-variable-table { enabled = true }
    blob-string { enabled = false }
    indy-call { enabled = false }
    invokedynamic { enabled = false }
}
```
</details>

<details>
<summary><b>HEAVY</b> — STANDARD + blob-string + indy-call. ~+70% size, ~+15ms class load. For plugins you really don't want cracked.</summary>

```hocon
transformers {
    renamer { enabled = true, strategy = ALPHABET }
    string-encryption { enabled = true, strength = HEAVY }
    string-concat { enabled = true }
    class-literal { enabled = true }
    number-obfuscation { enabled = true }
    bogus-exception { enabled = true }
    flow-obfuscation { enabled = true, technique = ALL, complexity = 3 }
    opaque-predicates { enabled = true, type = MIXED }
    blob-string { enabled = true }
    indy-call { enabled = true }
    junk-code { enabled = true }
    access-flags { enabled = true }
    member-shuffler { enabled = true }
    source-scrub { enabled = true }
    local-variable { enabled = true }
    local-variable-table { enabled = true }
    invokedynamic { enabled = false }
}
```
</details>

---

## Benchmarks

Real-world test on **SHCommandBlocker-2.0.0.jar** (4 classes, 12.4 KB Paper plugin) with the HEAVY preset:

| Metric | Before | After | Δ |
|---|---|---|---|
| JAR size | 12 438 B | 21 759 B | **+75%** |
| Classes renamed | — | 3/4 | — |
| Methods/fields renamed | — | 32 | — |
| Strings encrypted (blob-packed) | 0 | 29 | — |
| `invokedynamic` call sites | 0 | 65 | — |
| Methods with flow obfuscation | — | 21 | — |
| Junk-code methods injected | — | 6 | — |
| Synthetic-flagged members | — | 14 methods + 18 fields | — |
| **CFR decompiled LoC** | **323** | **1145** | **+254%** |
| **CFR error/invalid-syntax markers** | **0** | **105** | — |
| Runtime overhead | — | <3% on first load, 0% steady state | — |

CFR produces *invalid Java syntax* (`if[i] = ...`, `void declaration`,
`void l`, `void true_`) on the blob decoder and junk methods — the output
will not compile, cannot be re-imported into an IDE, and spends significant
reviewer time on decoy methods.

---

## Configuration

Full reference: [`obfuscator.example.hocon`](obfuscator.example.hocon).

```hocon
input:   "plugin.jar"
output:  "plugin-obf.jar"
target:  auto                    # auto | paper | bungee | velocity | fabric | forge | plain

save-mapping: "mapping.txt"
verify-after-each: true
fail-on-verify-error: false

transformers {
    renamer             { enabled = true, strategy = ALPHABET }
    string-encryption   { enabled = true, strength = HEAVY }
    string-concat       { enabled = true }
    blob-string         { enabled = true }
    indy-call           { enabled = true }
    flow-obfuscation    { enabled = true, technique = ALL, complexity = 3 }
    opaque-predicates   { enabled = true, type = MIXED }
    # ... etc
}

exemptions = [
    "com.example.MyPlugin.MyListener",       # full class
    "com.example.api.**",                     # package recursive
    "com.example.MyCommand#onCommand",        # method
    "@org.bukkit.event.EventHandler"          # by annotation
]

auto-exempt {
    paper    = true   # @EventHandler, CommandExecutor, JavaPlugin lifecycle
    fabric   = true   # @Mixin, @Inject, @Overwrite
    forge    = true   # @Mod, @EventBusSubscriber
    bungee   = true
    velocity = true
}
```

---

## Retrace

Deobfuscate stack traces using the mapping file:

```bash
java -jar obfuscator.jar retrace --mapping mapping.txt --trace error.log
```

The tool resolves class, method, and field references; field mappings can
optionally omit the descriptor.

---

## CLI reference

```
Usage: obfuscator [-v] [--auto] [--dry-run] [--show-mapping]
                  [--config=<cfg>] [--input=<in>] [--output=<out>]
                  [--save-mapping=<map>]

  --input           Input JAR
  --output          Output JAR
  --config          HOCON config file (overrides CLI flags)
  --auto            Auto-detect target from plugin manifest / imports
  --save-mapping    Write original → obfuscated name mapping
  --show-mapping    Print the mapping to stdout (implies --dry-run on output)
  --dry-run         Analyse only, do not write output JAR
  -v, --verbose     Trace-level logging

Subcommand:
  retrace --mapping FILE [--trace FILE]
```

---

## Architecture

```
core/          Obfuscator, ClassPool, JarWriter, TransformerPipeline,
               FrameComputingClassWriterFactory (pool-aware COMPUTE_FRAMES)
transformers/  16 transformer implementations (see table above)
analysis/      DependencyAnalyzer, InheritanceAnalyzer, AnnotationScanner
config/        ObfuscatorConfig (HOCON), RuleEngine, ExemptionResolver
compat/        PaperPluginCompat, BungeeCompat, VelocityCompat,
               FabricCompat, ForgeCompat, TargetDetector
verify/        BytecodeVerifier (CheckClassAdapter wrapper)
retrace/       RetraceTool
cli/           Main (picocli)
```

---

## Contributing

Tests live in `src/test/java`. `mvn -B test` runs them. End-to-end tests
assemble a minimal in-memory JAR, run the full pipeline, reload the output
in a fresh `URLClassLoader`, and invoke the resulting classes to verify
runtime behaviour is preserved.

## License

[MIT](LICENSE)
