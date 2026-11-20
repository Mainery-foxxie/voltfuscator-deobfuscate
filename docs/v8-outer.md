# Inspected v8.0 outer-string recovery

`src/outer_v8.rs` exposes `pub fn recover(source: &str) -> Result<(String, serde_json::Value), String>`.
The coordinator must export/integrate the module; this change intentionally does not edit `lib.rs`, `main.rs`, or `Cargo.toml`.

The pass matches the complete outer helper token stream, allowing bijective identifier renaming and explicit numeric parameter slots. It then validates the index checksum, index bounds/count, every ASCII85 record, decrypted length, and decrypted checksum. It discovers the bootstrap/application decoder aliases from their factory wiring. Seed candidates are zero and the square of the inspected admission constant; every record must validate against exactly one candidate, and every replaced call must use the seed appropriate to its phase.

| Original | Index / pool | Bootstrap / application decoder | Seed-zero / seeded records | Application seed | Replaced calls |
| --- | --- | --- | --- | --- | --- |
| `script.lua` | `HK` / `HZ` | `lf` / `BC` | 41 / 92 | 102333456 (`0x2784²`) | 654 (92 bootstrap, 562 application) |
| `fetched (2).lua` | `Rr` / `RN` | `Rt` / `hf` | 35 / 54 | 1088076196 (`0x80da²`) | 362 (73 bootstrap, 289 application) |
| `fetched (4).lua` | `wk` / `wG` | `Rne` / `Ry` | 41 / 87 | 2179675969 (`0xb65f²`) | 654 (92 bootstrap, 562 application) |

All 350 indexed records validate; all 1,670 recognized constant calls are replaced. There are zero remaining dynamic calls to those outer aliases in these three originals. JSON evidence includes each record's ID, pool offset, encoded length, seed, and decoded bytes.

Only lexical direct calls with one integer-literal argument are replaced. Comments, strings, member calls, decoder definitions, original wrapper, admission checks, and application VM remain. Decoder shadowing, assignment, extra seed-setter references, changed helper operations, corrupted pools, and wrong seed phases fail explicitly. Dynamic arguments remain in the partial source and are counted. The block scanner covers the inspected statement syntax; arbitrary Luau syntax/dataflow and other v8 builds are not claimed supported.

## Verification

`cargo test --test outer_v8 -- --nocapture`: 15 passed. The initial stub failed all three sample tests (RED); negative seed-phase/shadowing tests also failed before their checks were added. Tests compile each resulting Luau chunk without invoking it. They independently evaluate only the complete, template-matched helper function expression in a restricted mlua environment (string library, no filesystem/network/load APIs, 16 MiB limit, five-second interrupt deadline), and compare all 350 original-helper outputs byte-for-byte against Rust results. No application entry is evaluated.

`cargo test --test recovery --test sample --test source`: 12 passed, two existing `CHESS_SAMPLE` tests ignored. A full `cargo test` currently stops at concurrently added `tests/batch.rs::batch_reports_each_file_deduplicates_and_preserves_inputs`, whose CLI invocation receives `Usage: chess-deobf INPUT.luau OUTPUT_DIRECTORY`; that integration is outside this module's exclusive files.

Latest focused run artifacts, relative to the project root:

- `output/v8-probe-new/script.lua-1795187016702079800/`
- `output/v8-probe-new/fetched (2).lua-1795187016624135400/`
- `output/v8-probe-new/fetched (4).lua-1795187017261435200/`

Each contains `outer.partial.luau`, `stats.json`, and `input.sha256`. Tests verify original hashes again after recovery:

| Original | SHA-256 |
| --- | --- |
| `script.lua` | `3f258e8be10a03567670d3570efc19a1814a71c5d0779e4617cb35e995a2d0a8` |
| `fetched (2).lua` | `7cb2eb4bbca0a5fe6a677aa1f03e3afa30bb27df89ae0d9aecfbab37c4440725` |
| `fetched (4).lua` | `62ca6a5037cb1b77012dd9a7e3790ce383e7993b5765766841fef370f8f7f6c0` |

These artifacts are **partial outer decoding**, not full devirtualization or proof of whole-program equivalence. Inner pool decoding, VM semantics, admission behavior in Roblox, and application effects remain unverified.
