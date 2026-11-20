# Voltfuscator and Cryptnek recovery CLI (Rust)

This Rust tool decodes and devirtualizes the supplied `chess.luau` sample. The `--lift` path recovers 18 prototypes, 383 reachable records and 38 opcode variants, then emits ordinary Luau functions, conditionals and loops with decoded constants. The generated source contains no VM dispatcher or encrypted bytecode. Variable names are generated logical registers; the original variable names cannot be recovered. Other Voltfuscator 8.1 builds may use different names, keys and layouts and are not guaranteed supported.

The original sample is never overwritten. The `--auto` command routes validated exact builds to their supported recovery stage and keeps string-only results explicitly partial. The design follows the Bacon example's extraction/decoding/lifting/verification stages; its Bacon-specific decoder is not reused.

## CLI

Use Rust 1.100 or newer:

```powershell
cargo build --locked --features bot --bins
.\target\debug\chess-deobf.exe "C:\path\chess.luau" "C:\path\new-stage1"
.\target\debug\chess-deobf.exe --lift "C:\path\new-stage1\chess.outer-decoded.luau" "C:\path\new-lifted"
.\target\debug\chess-deobf.exe --auto "C:\path\script.lua" "C:\path\new-auto-output"
```

`--auto` writes a machine-readable `report.json` and refuses an existing output directory. It accepts the exact inspected Cryptnek and chess v8.1 samples, uses validated outer adapters for supported additional Voltfuscator inputs, and reports unsupported inputs without inventing source. Clean lifts and partial string-decoded results are distinguished in the report; inspect `artifacts`, `stage_results`, `coverage`, and `limits` before using an output.

Both output directories must be new. The lift produces:

- `chess.lifted.luau`: readable source with the VM removed; no application code runs during extraction.
- `lifted-ir.json`: prototypes, source PCs, successors, operands, closure captures and per-instruction constants.
- `lift-report.json`: actual coverage counts, syntax validation and verification limits.
- Native-decoded loader, strings and metadata for inspecting the transformation.

The supplied sample's deliverable is `output/devirtualized/chess.lifted.luau`. Recovered URLs remain references in the output; the recovery command does not fetch them.

For a named, manually cleaned version of that verified lift, use `output/devirtualized/chess.clean.luau` (also delivered as `Downloads/chess.clean.luau`). It replaces register temporaries with service and callback names, table literals and ordinary loops. The sample regression compares this file with both the generated lift and original interpreter. This file is a cleanup of the supplied chess sample; the CLI does not automatically apply these sample-specific names to other inputs.

For the preserved partial-recovery pipeline:

```powershell
.\target\debug\chess-deobf.exe --recover "C:\path\script.luau" "C:\path\new-output-directory"
```

The destination must not already exist. Outputs include:

- `result.partial.luau`: the script with recovered string calls substituted, with a partial-recovery notice.
- `report.json`: actual counts, original SHA-256, syntax-validation result, and recovery limits.
- `stage1/outer-strings.tsv`: records whose length and checksum validate.
- `stage2/native-strings.tsv`: native-loader strings recovered using validated dispatch contexts.
- `stage2/instructions.json`: 103 records from a linear root scan, with 100 standard frames captured before handler execution and three unresolved compound records. Constant handles apply to their individual instruction; they are not global pool indices. Reachability and all operand meanings remain unverified.

The engine uses Rust for scanning, outer decoding, native state recovery, source emission, artifact generation and the CLI. It embeds Luau through `mlua` to evaluate extracted decoder helpers. Its extraction loader replaces the application entry point with a capture and exposes no filesystem, network, package loading or executor APIs to Luau. The interpreter has a 256 MiB allocation limit and a 30-second interrupt deadline. This is a restricted interpreter, not a hardened operating-system sandbox. The partial artifact retains the original VM; the lifted artifact removes it. Syntax validation alone does not establish behavioral equivalence.

## Batch attempts for additional samples

```powershell
.\target\debug\chess-deobf.exe --batch "C:\path\voltfusctarosamples" "C:\path\new-batch-output"
.\target\debug\chess-deobf.exe --decode "C:\path\sample.lua" "C:\path\new-single-output"
```

The batch attempts every `.lua`, `.luau` and `.txt` file in the supplied directory. It decodes unique hashes once, then writes an individual result for every source filename. Each worker is limited to 90 seconds; inputs are limited to 4 MiB. Originals are checked for changes. Existing output directories are refused.

`--decode` attempts one file and writes `report.json` plus `source.partial.luau` when decoding succeeds. A completed attempt can report `unsupported`; inspect the report or batch manifest for the recovery outcome. Version banners prioritize adapters, while recognition and validation of the decoder determine acceptance. The existing chess 8.1 commands above remain separate.

`RESULTS.md` is the readable index, and `manifest.json` records all outcomes. Accepted string-decoded source is named `<original filename>.partial.luau` and must pass the Luau compiler. Every input gets `<original filename>.report.json`; unsupported inputs receive a report without a fabricated source file. Internal stage records are retained under `stages/`.

Batch success means the attempts completed. It does not mean all inputs were devirtualized. These additional format adapters recover verified string layers only; their output can retain the protected VM and original application entry. Do not execute an artifact merely because its syntax check passed. The Discord bot routes through `--auto`; the legacy `--recover` option remains available for its original partial-recovery workflow.

The final 2026-11-20 corpus run is saved in `Downloads/Voltfuscator-recovery-final-2026-11-20/`. Its completed manifest accounts for **59 files / 44 unique hashes: 55 partial, 4 unsupported, 0 fully devirtualized**. The built CLI was copied to `output/batch-final-worker/chess-deobf.exe` before execution, so the run did not lock Cargo's executable. The earlier baseline remains intact at `Downloads/Voltfuscator-recovery-2026-11-20/`.

| Adapter | Partial files | Partial unique inputs | Calls replaced, all files | Calls replaced, unique inputs |
| --- | ---: | ---: | ---: | ---: |
| Nyx | 39 | 27 | 23,069 | 15,828 |
| Legacy | 13 | 11 | 460 | 386 |
| v8.0 | 3 | 3 | 1,670 | 1,670 |
| Total | 55 | 41 | 25,199 | 17,884 |

All 59 original SHA-256 hashes match `output/sample-inventory.json` after recovery and verification. All 59 reports were checked; all 55 emitted partial artifacts match their stage copies byte-for-byte and passed an independent compiler-only check using the installed Luau compiler. `verification.json` records per-input source/report/artifact hashes, manifest and worker hashes, exact replacement totals, and unsupported reasons. Compilation does not execute application code or establish behavioral equivalence.

The final unsupported inputs are `TOXIC_HUB.lua`, `fetched (22).lua`, `fetched (45).lua`, and `fetched (51).lua`. Their reports preserve the adapter rejection reasons: unrecognized or rewritten layouts, and ambiguous transformed syntax for `fetched (22).lua`. No partial source is emitted for rejected inputs. `fetched (35).lua`, rejected in the baseline, now has a compiled partial result. The full suite is run separately from this corpus verification.

## Cryptnek

```powershell
.\target\debug\chess-deobf.exe --cryptnek "C:\path\sample.lua" "C:\path\new-cryptnek-output"
```

The dedicated `--cryptnek` path remains available for the inspected Cryptnek build; `--auto` routes that exact build and publishes its clean source plus anti-tamper report. Acceptance applies to the exact inspected SHA-256; arbitrary Cryptnek builds are not guaranteed supported. Use the reports to assess coverage and recovery limits.

The inspected CoPlay build is admitted by exact SHA-256 while its opcode semantics remain build-specific. The Rust decoder validates the packed payload and encrypted bytecode, evaluates an arithmetic-only bootstrap, and unlocks all nine prototype graphs. Source emission specializes known selector states, preserves unknown branches and shared capture cells, and folds proven string-decoder calls to literals. See `docs/cryptnek-recovery.md` for the format evidence and current verification limits.

The delivered `Downloads/CoPlay_Legit_Trivia_Only.lifted.luau` contains 691 lines with the bytecode encryption and VM dispatcher removed. It accounts for all nine prototypes and 2,369 raw reachable instruction records; 40 string literals were materialized. Generated register names and explicit result packs remain. Supporting IR, source maps, decoded constants and the recovery report are in `Downloads/Cryptnek-recovery-2026-11-20/`. The local-sample regression compares the lift with the original interpreter using inert fixtures; real services and downloaded modules are not validated.

## Discord bot

1. Create an application and bot in the Discord Developer Portal.
2. Enable **Message Content Intent** under Bot → Privileged Gateway Intents.
3. Invite it with View Channel, Send Messages, Read Message History, and Attach Files permissions.
4. Set the token and allowed user IDs in the process environment, then run the built bot:

```powershell
$env:DISCORD_TOKEN = "YOUR_BOT_TOKEN"
$env:DISCORD_ALLOWED_USERS = "YOUR_NUMERIC_USER_ID"
.\target\debug\voltfuscator-bot.exe
```

Send `!deobf` with one `.luau`, `.lua`, or `.txt` attachment. The bot routes through `--auto`: it attaches clean source and validation reports for a clean lift, a clearly partial artifact and report for string-only recovery, or the diagnostic report alone for unsupported input. Replies are visible in that channel; use a direct message for private samples.

The `.env.example` file documents the names; the program reads environment variables, not `.env` automatically. Never commit or paste a real token into source code.

Only configured users are accepted. One recovery runs at a time; busy requests are rejected. Inputs are limited to 2 MiB, CDN downloads to 30 seconds, and worker processes to 90 seconds. Each job uses a temporary directory and a separate CLI process, which does not inherit the Discord token. Attachment URLs must use Discord's HTTPS CDN; redirects are disabled. The bot does not fetch URLs embedded in scripts.

For a bot shared with untrusted users, place the worker in an isolated VM/container. Building this project does not connect to Discord or publish any samples.

## Checks

```powershell
cargo test --locked --features bot --all-targets
cargo fmt --check
```

To include the regression against the supplied original sample:

```powershell
$env:CHESS_SAMPLE = "C:\path\chess.luau"
$env:CRYPTNEK_SAMPLE = "C:\path\CoPlay_Legit_Trivia_Only.luau"
cargo test --locked --features bot --all-targets -- --include-ignored
```

The suite checks decoding, restricted interpreter capabilities and source-emitter behavior, including branch polarity, loops, missing constants and multiple returns with nil values. The sample regression also runs the original interpreter and generated source separately against local Roblox stand-ins, invokes every recovered UI callback, and compares recorded effects across three scenarios. This covers normal execution, an empty job ID, quest and purchase errors, and an absent clipboard API. It does not validate remote services, downloaded modules or live Roblox behavior. The bot has not been tested against Discord with a live token. See `docs/recovery.md` for evidence and limits.

The batch CLI integration was checked with `cargo test --locked --target-dir target-integration --test batch`: four tests passed, covering per-file reports, hash deduplication, preserved originals and existing outputs, unsupported UTF-8/oversized inputs, structure-based routing despite a misleading banner, and individual partial source artifacts for supported duplicates. `target-integration` was used to avoid Windows executable locks from concurrent work; it is not required by the CLI.

Final integrated verification on 2026-11-20: `cargo test --locked --features bot --all-targets -- --include-ignored` passed **62 tests** with both `CHESS_SAMPLE` and `CRYPTNEK_SAMPLE` set. `cargo fmt --check` passed, and `cargo build --locked --features bot --bins` built both executables. Existing chess recovery and its cleaned standalone artifact remain verified.
