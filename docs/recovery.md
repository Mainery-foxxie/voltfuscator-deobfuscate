# Recovery evidence and limits

Input: the supplied `chess.luau`, 493,949 bytes, SHA-256 `8ec257c05b1e57e60631fe27da430cb50993f37b7fd25c76bab5704420db3ec6`. The banner identifies Voltfuscator v8.1. This adapter depends on the inspected sample's names, constants, and loader layout.

## Established stages

1. The outer index uses a variable-length radix-42 representation. Each pool record uses ASCII85 and a stateful subtraction cipher. Rust validates the record length and checksum before accepting any recovered string. All 130 records validate; 672 tokenized decoder calls are replaced.
2. Native loader states use two Feistel round schedules. Candidate states are checked against each block's decoded seal predicate before its string-decoder context is accepted. All 210 `gB` and 101 `zzM` block contexts validate. This replaces 1,332 decoder calls with zero unresolved calls at that stage.
3. Extraction replaces `return dv(dM,dB,nil,{},0,47,true,dc)` with a capture of the root reader and its metadata. The restricted Luau environment supplies computation libraries and small in-memory loader probes. It has no filesystem, network, executor, or dynamic module loading APIs.
4. The root reader yields 103 records across 492 address units in a linear scan. Before standard handler dispatch, the patched loader captures the active frame and suppresses the handler call. This captures 100 standard frames; three compound records are explicitly unresolved. A linear scan does not establish the real control-flow graph or that every decoded record is reachable program code.

The native operand reader in block `13350458` encodes pool-backed operands as a pool slot multiplied by 1024 with an optional 256 flag. They remain encoded handles in `instructions.json`. Constant lookups must occur while the corresponding protected frame is active. The harness originally omitted the interpreter's context field, causing `C071`; supplying that field allowed contextual lookup.

Protected strings are wrappers whose descriptor holds a guarded byte-reader function. The inspected byte reader, block `7348301`, computes a byte by advancing its seed with modular multiplication, then subtracting the low byte of that state from ciphertext after a five-byte header. Rust evaluates that arithmetic while the extraction loader bypasses the caller-admission guard. The sample regression checks the first materialized values independently: PC 5 → `"game"`, PC 9 → `"GetService"`. The next record also yields `"Players"` during inspection. This verifies those recovered strings, not the whole constant pool or program.

## Deliverable status

`result.partial.luau` is the original loader and virtualized program with the two string-call layers substituted. It is checked with the Luau compiler. `instructions.json` is an analysis intermediate with per-record constants, handler tags, encoded operands, errors, and unresolved cases. `report.json` includes measured stage counts, VM coverage, and input hash.

The preceding description applies to the preserved `--recover` path. It is superseded for source recovery by the separate `--lift` path below. The old linear records remain analysis artifacts and must not be treated as a global constant pool or a source lift.

## Source devirtualization

`src/lift.luau` traverses both successors of conditional records and decodes nested prototypes recursively. It restarts and replays a valid path from the function entry before exploring an alternate branch, preserving the lazy reader's state. It does not execute application handlers. Correct operand shifts come from metadata slot 1 for primary fields and slot 2 for extra words. Fused operand offsets and successors were derived from the native handlers, rather than inferred from adjacent encrypted bytes.

The resulting graph has 18 prototypes, 383 reachable records and 38 opcode variants. The 15 immediate root callbacks include the quest function, UGC helper, 11 claim callbacks and two clipboard callbacks; there are two further nested functions. No reachable handler remains unmapped. Errors in decoding, captures, constants or emission cause the command to fail; an absent constant cannot silently become nil.

`src/source.rs` expands fused handlers, resolves contextual operands, reconstructs closures and structures the graph into functions, conditionals and loops. It preserves fixed arguments before variable argument lists and multiple-return lengths, including nil values. The type predicate used by this sample is reduced to its observed type test. Register names (`r0`, `r1`, etc.) are generated names, not recovered author identifiers. External module calls and URLs are retained. The Luau compiler checks the emitted source before it is delivered.

Artifacts are `output/devirtualized/chess.lifted.luau`, `lifted-ir.json` and `lift-report.json`. The IR preserves prototype names, PCs, edges, capture sources and instruction-specific constants so the source can be checked against the native interpreter. `lift-report.json` reports extraction and compiler results; behavioral verification is performed by the separate sample regression.

The additional `chess.clean.luau` artifact is a manual readability cleanup of that fully decoded application: 158 lines with named services, a 35-row quest table and ordinary callback functions, replacing the 765-line register lift. It does not contain the custom interpreter or generated register variables. The original lift and IR are retained. This cleanup is specific to the recovered chess program, and does not add version support or a generic optimizer to the CLI.

## Behavioral verification

The sample regression independently runs the original outer-decoded loader's `qf` entry, the generated lift and the clean source in separate restricted Luau interpreters with the same local stand-ins. The reference uses the original bytecode reader, constant facade and application handlers; the extraction patches are not applied to it. Only the outer invocation is selected directly to supply the test environment. All network, Roblox and module effects are local functions supplied by `tests/fixtures/roblox-standins.luau`. Only the slower original-interpreter test fixture gets a 90-second deadline; production extraction retains its 30-second limit.

Each interpreter creates the 14 expected buttons and invokes all their callbacks. The regression checks all 35 quest calls, 11 UGC requests, both clipboard links, notifications, log messages and waits. Deterministic snapshots compare all recorded arguments and effects between the reference and generated source. Scenarios cover a normal job ID and successful calls; an empty job ID with a quest failure and purchase failures; and an unavailable clipboard function. The independent fixtures assert remote names, method self arguments, call arities, UGC IDs and nil-preserving returns.

This establishes agreement for those controlled scenarios. It does not prove equivalence for arbitrary hostile metatables, custom executor hooks, changing downloaded modules, real server behavior, or all possible inputs. No recovered URL was fetched and no live game action was performed. The output is a complete source lift of the decoded reachable program in this sample; it is not a universal Voltfuscator decompiler.

The Discord bot shares this partial pipeline through a separate worker process. It returns the partial artifact and report, enforces an allowed-user list and one active job, and bounds input/download/job sizes and durations. No live Discord interaction has been tested without a user-supplied token. The embedded interpreter is restricted but is not an operating-system security boundary.
