# Legacy Voltfuscator outer string recovery

`src/outer_legacy.rs` exposes:

```rust
pub fn recover(source: &str) -> Result<(String, serde_json::Value), String>
```

This is **partial string recovery**, not application devirtualization. The supplied
v7.5 and v7.6 banners reference `https://dsc.gg/Obfuscating`; the URL is treated as
sample text and is never fetched. Application VM code, decoder setup, noise,
environment accesses, banner side effects, and dynamic decoder calls remain.

## Decoder evidence and execution boundary

Both inspected families unpack a length-prefixed encoded string pool, reconstruct
a ChaCha block/stream helper, decode a shuffled ASCII85 alphabet, resolve sealed
per-string keys, and shuffle the pool before application entry. v7.5 stores its
sealed key records as fixed 44-byte records. v7.6 uses an encrypted index and
8-byte admission or 40-byte sealed records. The original helper checks record
lengths and admission/resolve values. These checks run when a candidate constant
call is decoded; a nil/rejected admission is never replaced with a guessed value.

The adapter accepts eleven exact pre-application prefix hashes covering thirteen
supplied files. Prefix hashing also covers the wrapper and noise before the
helper, so an inserted environment mutation cannot silently reuse an approved
decoder. An unknown or edited prefix returns an unsupported error. This is a
deliberate corpus-limited implementation, not a claim of support for every build
that shares the banner.

Only the slice beginning with the packed string local and ending with the first
three-argument forwarding table runs inside `vm::restricted_lua`: 256 MiB and a
30-second interrupt deadline, without host/network/filesystem APIs. No banner
callback, outer table method, application entry, or full sample is executed.
Trailing underscores in numeric tokens are removed only in this isolated slice
and constant arithmetic expressions so the installed runtime accepts them.

The arithmetic evaluator accepts numeric/punctuation tokens only, requires an
actual finite integral runtime number, and bounds accepted arguments to the
exact-integer range. A string such as `48 .. 10` is not coerced to a number.

## Source substitution

Forwarding tables must match the observed `function(a,b,c) return decoder(a +/-
offset,b,c) end` structure. Token offsets preserve strings and comments. Block,
function parameter, local, and loop bindings prevent matching shadowed names.
Only immutable, private alias tables are eligible; alias mutation, escaping
references, and ambiguous shadow initializers suppress that table's replacements.
Repeat/until application scopes are explicitly unsupported.

Only successful string results become byte-preserving Lua literals. Dynamic
arguments, side-effectful arguments, rejected admissions, and boolean admission
calls stay unchanged. The report includes replacement/dynamic/rejected counts,
unsafe alias references, slice offsets, slice/prefix hashes, and unresolved VM
boundaries. Returned status is always `partial`.

## Supplied corpus coverage

| Filename | Banner | String calls replaced | Dynamic calls preserved |
|---|---|---:|---:|
| fetched (17).lua | 7.6 | 36 | 786 |
| fetched (37).lua | 7.6 | 40 | 786 |
| fetched (42).lua | 7.6 | 38 | 786 |
| fetched (43).lua | 7.6 | 38 | 786 |
| fetched (44).lua | 7.6 | 39 | 10454 |
| fetched (46).lua | 7.6 | 36 | 786 |
| fetched (47).lua | 7.6 | 36 | 1024 |
| fetched (48).lua | 7.6 | 38 | 6026 |
| fetched (49).lua | 7.6 | 36 | 1158 |
| fetched (50).lua | 7.6 | 39 | 1022 |
| fetched (52).lua | 7.5 | 36 | 397 |
| fetched (53).lua | 7.5 | 42 | 397 |
| fetched (54).lua | 7.5 | 6 | 798 |

All thirteen inputs were attempted: 460 string call replacements in total,
including duplicate files. `fetched (54).lua` has a local shadow initializer named
`B`; the conservative alias check preserves the corresponding outer table, so
only six calls from other verified alias tables are substituted.

## Verification and integration

`cargo test --test outer_legacy -- --nocapture` exercises the thirteen supplied
files, checks wrapper preservation and known literal `"t"`, checks arithmetic
numeric forms and concatenated calls, rejects altered prefixes, and covers
shadowing, alias mutation/escape, invalid admission, and effectful arguments.
Each recovered corpus output is compiled by Luau without execution. Corpus tests
use `VOLTFUSCATOR_SAMPLE_DIR`, defaulting to the sibling `voltfusctarosamples`
directory, and skip external fixtures if that directory is absent.

The module and tests are self-contained within the delegated file ownership.
The parent session must export `outer_legacy` from the library and route its
legacy family to `recover`; this task does not edit library exports, CLI, Cargo,
other adapters, or source samples. No probe files or decoded applications are
written by this adapter or its tests.
