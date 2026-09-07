# Investigation Workflows

Load only the workflow that matches the request. Preserve the hard safety
boundary and output/evidence contracts from the main skill.

If the request already names one capability or exact selector, begin at that
matching section. General triage is the fallback for open-ended questions, not
a prerequisite for every narrow command.

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

## Static Relationships

- Use `inspect-flow` for a root-centered bounded neighborhood.
- Use `call-graph` for static call edges and unresolved callsites.
- Use `data-xrefs` for exact code/data reference questions.
- Use `aarch64-refs` for AArch64 formed-address chains.

Follow only progressing record pages or bounded widen actions. Do not treat
traversal order as runtime order.

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
