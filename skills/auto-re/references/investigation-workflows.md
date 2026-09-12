# Investigation Workflows

Load only the workflow that matches the request. Preserve the hard safety
boundary and output/evidence contracts from the main skill.

If the request already names one capability or exact selector, begin at that
matching section. General triage is the fallback for open-ended questions, not
a prerequisite for every narrow command.

## External Source Retrieval Boundary

Auto-RE does not ship an upstream-source downloader, network retry policy,
source cache, or GitHub-token configuration. Its distribution installer is
offline. If source comparison needs GitHub content, retrieval belongs to the
trusted host or agent harness, not the static analyzer. Host tooling such as
`gh` may use `GH_TOKEN` or `GITHUB_TOKEN`; these are not Auto-RE settings and
credentials must never be printed or copied into analysis artifacts.

Where available, an authenticated host-side contents API can avoid raw-download
host restrictions. Pin the repository, commit and source path; retain the content
hash and host retrieval status. Reusable host caches should be workspace-local
and keyed by that identity, not a mutable tag alone. Distinguish empty content
from rate limiting, denied access, missing files and network failures. Unavailable
source is unresolved evidence, not proof that code or a library version is absent.
Never execute fetched sources or sample-derived helpers. Report fetch failures
to the host-tool owner with sanitized diagnostics; an Auto-RE update cannot fix
an external harness downloader that is not part of this repository.

## General Triage

```bash
auto-re-cli report <input> \
  --format json \
  --json-profile ai \
  --sections binary,summary,inspections,flow,functions,types \
  --limit 8 \
  --bundle-dir <results>/triage.bundle \
  --output <results>/triage.bundle/manifest.json
```

Validate the manifest, then prioritize:

1. binary format/architecture/input identity;
2. warnings and truncation;
3. language/protection evidence;
4. high-signal findings and flow root;
5. one emitted continuation.

Do not load every section if the user's question needs only one.

## Entry Or Interesting Function

1. Select a function address from validated report evidence.
2. Run:

```bash
auto-re-cli function <input> --addr <pc> --format json \
  --output <results>/function-<pc>.json
auto-re-cli dump-il <input> --level custom --addr <pc> --format json \
  --output <results>/custom-il-<pc>.json
auto-re-cli inspect-passes <input> --addr <pc> --format json \
  --output <results>/passes-<pc>.json
```

For a large function, prefer an emitted `slice-function` action. Select by an
existing call target or string reference when available; this is navigation,
not new recovery.

## PE Runtime-Function Bounds

When installed help lists `function-bounds`, query a PE x64 VA before manually
selecting a byte range. The result is exception-directory metadata, not a guessed
padding boundary. Use `range.begin_va` and exclusive `range.end_va` only when
`status=validated_metadata_range`; retain `unwind_rva` and directory `entry_rva`
for provenance. `not_found` can mean a leaf without metadata, not missing code.
Malformed, unsupported and budget-exceeded states do not authorize guessed bounds.
A metadata record may describe a fragment rather than an entire source function.

## Compare Selected Functions Across Builds

When installed help lists `compare-functions`, choose each function independently:

```sh
auto-re-cli compare-functions <left-binary> <right-binary> \
  --left-addr <left-VA> --right-addr <right-VA> --format json
```

Each side can instead use its own `--left-symbol` or `--right-symbol`. The
command compares bounded decoded instruction text, not byte signatures or
semantic equivalence. Default 256 instructions per side, hard maximum 512;
inspect per-side warnings and limit flags. Instruction address labels are omitted,
but operands, memory addresses and constants are preserved, so relocation can
still create meaningful-to-review differences. Equal retained text is not proof
of complete function identity; a missing byte pattern is not proof of absence.
Single ELF, PE and Mach-O objects of the same architecture are supported, not raw
or universal containers. Use `diff` separately for archived analysis results.

## Static Relationships

- Use `inspect-flow` for a root-centered bounded neighborhood.
- Use `call-graph` for static call edges and unresolved callsites.
- Use `data-xrefs` for exact code/data reference questions.
- Use `aarch64-refs` for AArch64 formed-address chains.

Follow only progressing record pages or bounded widen actions. Do not treat
traversal order as runtime order. For string-based role hypotheses, inspect the
selected function first (or use `inspect-flow --addr <pc> --depth 0`). When
expanding callees, retain each string's owning node and instruction use site;
callee-only strings must not rename or label the caller. Compare known control
functions before accepting a heuristic subsystem label.

For PE x86-64 import jumps, newer analyzers can label proven one-hop callers as
`DLL!Function`. Keep the encoded branch target (the thunk), `pe_import.slot_address`
(the IAT slot) and optional `pe_import.thunk_address` separate. A resolved static
import name does not prove runtime binding; indirect thunk-tail graph edges stay
inferred. Unsupported jump forms and longer chains remain unresolved.

## String Pools And Table Bases

No exact reference to a name does not prove the name is unused. Names may live
in a pool accessed through an anchor, an index or an unresolved hash. Inspect
nearby strings and their exact addresses first. When installed help lists
`--address-end`, query a known bounded pool interval:

```sh
auto-re-cli data-xrefs <input> --address <pool-start-VA> \
  --address-end <exclusive-end-VA> --direction data-to-code --format json
```

Inspect each row's exact destination, owning function, instruction provenance
and `matched_selector_fields`, then narrow to the actual anchor address. A row
for the anchor does not establish which member was accessed. The query filters
existing retained evidence only; it does not infer stride, record layout or hash
semantics, and unnamed bases without retained evidence may still be absent.
Follow emitted pagination with both interval bounds unchanged.

## Go

```bash
auto-re-cli inspect-go <input> --format json --json-profile ai \
  --output <results>/go.ai.json
auto-re-cli inspect-types <input> --format json \
  --output <results>/types.json
```

Use emitted inventory pagination and selected-function actions. Keep compiler
wrappers, package-init records, `pclntab` names, interface hints, and ABI proof
states separate. Do not claim scheduler/runtime behavior, source package init
order, concrete arguments, receivers, or complete source recovery unless an
explicit proof field validates the specific fact.

## Obfuscated Or Stripped Go

1. Separate language detection from parsed metadata. Record build version,
   `pclntab` status and recovered-name count; zero names is not zero functions.
2. If inventory output repeats, compare selectors and discovery coverage before
   increasing `--limit`. Keep synthetic raw identities; do not invent Go names.
3. At an unresolved indirect call, inspect the exact callsite and its formed
   addresses/data references. A candidate target is not an accepted call edge.
4. For a large initializer or string helper, use the emitted `slice-function`
   action and retain the slice bounds. Prefer shared static IL evidence over
   copying an investigation's instruction simulator into a runnable helper.
5. Preserve conflicting string candidates, raw byte lengths and UTF-8 status.
   Printable output is not a proof. Keep init stores, globals and consumers as
   separate links until static evidence joins them.
6. Stop a repeated action with identical input/selector/budget and no new
   evidence. Report unresolved metadata, CFG or data-flow boundaries; do not
   turn missing static evidence into permission for runtime execution.

## Rust

```bash
auto-re-cli inspect-rust <input> --format json --json-profile ai \
  --output <results>/rust.ai.json
auto-re-cli inspect-types <input> --format json \
  --output <results>/types.json
```

Follow exact symbol/source-context actions. Demangled names, closure markers,
trait hints, enum source-shape markers, panic/drop evidence, and source paths
remain bounded static evidence. Do not claim ownership/drop order, concrete
trait implementors, source module ownership, Rust ABI, or runtime panic paths
without the exact accepted proof.

## PE Resources And Strings

```bash
auto-re-cli pe-resources <input> --format json --json-profile ai \
  --output <results>/pe-resources-0.json
auto-re-cli pe-strings <input> --format json --json-profile ai \
  --output <results>/pe-strings-0.json
```

Follow page actions by advancing only their returned offset. Preserve hierarchy,
encoding, source, invalid/truncated status, reference state, and provenance.
Never execute resource payloads or scripts. Absence from one bounded page is
not absence from the image.

## Raw Shellcode

After explicit architecture/base confirmation:

```bash
auto-re-cli report <blob> \
  --raw-shellcode \
  --arch <x86|x86_64|aarch64> \
  --base-address <base> \
  --entry-address <entry> \
  --format json \
  --json-profile ai \
  --sections summary,flow,functions \
  --limit 8 \
  --bundle-dir <results>/raw.bundle \
  --output <results>/raw.bundle/manifest.json
```

Omit `--entry-address` only when the base is the intended entry. Preserve all
raw-input flags in follow-ups. Never execute the blob or recovered payload.

## Packed Or Protected Input

Start with the general report. If it emits protection evidence:

```bash
auto-re-cli inspect-upx <input> --format json --json-profile ai \
  --output <results>/upx.ai.json
auto-re-cli inspect-vmp <input> --format json --json-profile ai \
  --output <results>/vmp.ai.json
```

Run only the relevant command. Read typed stage status, warnings, non-claims,
budgets, playbooks, and stop conditions. Do not equate detection with successful
unpacking or devirtualization.

## Batch And Regression Comparison

```bash
auto-re-cli batch <input-a> <input-b> \
  --output-dir <results>/batch \
  --sections binary,inspections,summary,types \
  --archive-bundles \
  --format json
```

Use `batch-replay` to verify archived samples and `batch-diff` or `diff` for
bounded comparisons. Match by input identity when possible. A semantic summary
is a bounded issue summary, not proof that unchanged fields are exhaustive.

## Closeout

Return:

- inputs and exact commands;
- created output paths;
- bounded verification/execution receipt paths and any log truncation;
- validated findings;
- conservative inferences;
- not-claimed/unresolved items;
- warnings, budgets, truncation, and stop conditions;
- confirmation that no target or target-derived artifact executed.

## Bounded Static Byte Evidence

`function <input> --addr <address> --format json` includes
`static_byte_evidence` for AArch64 little-endian functions. Read each window's
raw `bytes` (null means unknown), strict `encoding`, source instruction addresses,
callsite and symbolic stack origin. Scanned counts and `truncated` delimit the
window. These are reaching-store candidates; a call argument, runtime value or
complete string decoder is not thereby proved. Opaque effects and calls invalidate dependent bytes. Cross-block memory is
conservative; proven pair loops carry a separate bounded summary.

When static IL has identified a pair-permutation formula and its exact arrays,
`fold-pair-bytes` checks the arithmetic without a target instruction simulator.
For this controlled two-byte example, save a JSON plan:

```json
{"schema_version":1,"input_bytes":[10,20],"key_bytes":[0,1,0,1],"transform":{"mask":"xor","value_operation":"xor","constant_operation":"xor","constant":0,"key_bytes_used":4}}
```

```bash
auto-re-cli fold-pair-bytes <plan.json> --output <results>/byte-candidate.json
```

The result is `[8,22]`, marked `candidate` and `transform_proven=false`, with
plan/input/key hashes and all transform parameters. The fixed formula reads both
indexed bytes before writing either: `mask = (key1 XOR/SUB key2) + byte_index`,
then applies optional `mask_constant_operation` / `mask_constant` (default XOR
zero), followed by the value and output-constant operations using byte arithmetic. Key bounds are independent of output length. Unknown indices,
odd bounds and out-of-bounds accesses stop with unresolved status and no partial
plaintext. Never select or validate a formula merely because its output looks
readable. Keep CFG/loop-bound and parameter provenance beside the plan; unsupported
closure or jump-table relations remain unresolved. This command accepts only
bounded numeric data and fixed arithmetic choices, never scripts or instructions.

For bytes loaded from the executable, use one immutable input snapshot:

```bash
auto-re-cli recover-bytes <input> --addr <address> --max-instructions-per-function 256 --output <results>/bytes.json
```

This bounded JSON command retains the input hash, file/virtual read ranges and
load/store provenance. It rejects ambiguous mappings, writable memory, BSS,
relocations affecting the read, and instruction/snapshot mismatches. Stack
loads, aliases and partial MOVK writes retain unknown bytes rather than zero.

`pair_loops` records an automatically proved def-use relation when the bounded
CFG has a unique cycle path, zero initial counter, increment two, checked even
key bound, disjoint key/cipher storage and both byte loads before both stores.
The proof is independent of register names and text readability; it retains
setup and loop instruction addresses. Unmatched loops remain unresolved. A
proved transform is still a static candidate and does not prove runtime
reachability, caller arguments, source identity or network use.

For container slices, `selected_slice` records the selected architecture/range;
`input_sha256` covers the complete input and `file_offset` remains relative to
the original file. `memory_basis=read_only_after_fixups` records Mach-O's explicit
`SG_READ_ONLY` condition. The segment name alone never authorizes recovery.

`object_slot_links` records scalar loads, stores and register-mediated copies
using symbolic base origins, offsets and widths. Copies distinguish truncation
and zero extension, retain the source load address, and stop across unknown
calls or redefinitions. These links do not require Go build-version metadata;
they do not establish allocation ownership, capture names or initializer order.

`state_chains` folds byte stores only when a guarded table has a unique initial
state, constant transitions and a proved acyclic path to return. It retains
state order, a stable symbolic memory base and instruction addresses. Calls,
unknown stores, repeated states or unproved termination prevent a candidate.
