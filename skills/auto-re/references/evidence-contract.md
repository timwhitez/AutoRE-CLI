# Evidence And Artifact Contract

Load this reference before reading spill/bundle payloads, following generated
actions, or making a completeness claim.

## JSON Is The Automation Contract

Prefer JSON for machine use. Check:

- process exit status;
- `schema_version`;
- wrapper kind/profile;
- warnings and explicit status/reason fields;
- selector and budget records;
- completion/truncation fields;
- exact provenance attached to a claim.

Exit code `0` means the command completed. Exit code `1` is an analysis or
parsing failure. Exit code `2` is invalid CLI usage. A successful bounded
result can still be incomplete; use its completion and budget fields.

Raw-shellcode root functions warn that string-reference coverage is incomplete
without the original containing image. An empty `string_references` array is not
proof of no references, including when computed targets lie outside the supplied
slice. Keep recovered string facts separate from unresolved addresses; a numeric
target is not itself a string. Embedded object functions retain their own evidence.

## Decoded References Versus Byte Matches

A matching displacement or numeric operand is not sufficient reference evidence.
For x86, retained string use sites come from supported decoded operands; indexed
or segment-relative addresses may remain unresolved. An eight-byte pointer slot
requires a full-width pointer load, not a narrow load of part of its bytes.
Padding and bytes inside an instruction do not establish independent use sites.
External raw-byte scanners must keep candidates separate from decoded references;
zero retained rows still do not establish whole-program absence.

## Compiler Metadata Is Not An Ordinary Reference

PE exception-directory records and C++ exception metadata contain RVAs; their
presence does not establish a decoded callsite or ordinary data reference.
`data-xrefs` consumes retained typed AArch64 references and legacy string evidence,
not a blind four-byte RVA scan. Function-boundary metadata is not a caller edge.
Nearby `0x19930520`, `0x19930521` or `0x19930522` constants can be an investigation
clue, not proof that every nearby slot is EH metadata. Do not discard a real
decoded reference solely because it is near such a constant. External RVA-slot
scanners must identify their metadata/candidate evidence separately; those
session-specific scanners are not shipped by Auto-RE.

## String Ownership And Labels

A callee string belongs to the callee and its recorded instruction use site,
not to every caller that can reach that node. Do not flatten a callee walk into
caller strings or use it to assign a confident subsystem label; generic cleanup
and forwarding helpers can expose unrelated constants. Even a local string is
not proof of function purpose. Preserve raw identity beside `display_name` and
keep `inferred_role` confidence and evidence. Analyst labels based on a call
neighborhood remain heuristic and need independent checks against known controls.

## Bundles And Spills

A report bundle or direct spill is a command-owned artifact set. Before reading
payloads:

1. Require `owner == "auto-re-cli"`.
2. Require a supported manifest kind: `context_bundle` or
   `agent_spill_manifest`.
3. Require every `files[]` row to have `ownership == "command"`.
4. Resolve each `path` relative to the manifest directory.
5. Reject absolute paths, `..`, symlinks, non-files, duplicate paths, and paths
   outside the manifest directory.
6. Verify `bytes` and lowercase SHA-256.
7. Read only the validated paths.

Use the receipt route for this check:

```bash
python3 scripts/verify_bundle.py <manifest> \
  --receipt <receipts>/bundle-verification.json
```

Stdout is a bounded summary. Read the receipt for validated private file paths.
The validator rejects more than 64 payload rows or 64 MiB of aggregate declared
payload bytes before it creates a verified tree. Do not infer trust from a
directory name or raise these limits; narrow the requested sections or page.

`spill_summary.manifest_path` is only a pointer. Validate the referenced
manifest before loading the complete payload.

### Stable Workspace Across Tool Calls

Primary results use explicit `--result-dir`, `--output` or `--bundle-dir`; choose
a persistent workspace outside the input directory and installed Skill. Verified
copies use Python's temporary root. If the harness discards system temporary
files between calls, create a trusted workspace directory and set the same temp
root for every verifier and cleanup invocation. POSIX example:

```sh
mkdir -p ./analysis-results/verified-copies
TMPDIR="$PWD/analysis-results/verified-copies" python3 scripts/verify_bundle.py \
  <manifest> --receipt <receipts>/bundle-verification.json
TMPDIR="$PWD/analysis-results/verified-copies" python3 scripts/verify_bundle.py \
  --cleanup-receipt <receipts>/bundle-verification.json
```

Read the receipt's absolute verified payload paths between those two commands;
cleanup runs only after the final consumer. On Windows, set `TMPDIR`, `TEMP` and
`TMP` to the same existing absolute workspace directory before each `py -3`
invocation. Set environment variables before starting Python, not after its
temp-root cache is initialized. A mismatched cleanup root is rejected, not
silently searched or deleted. If the verified copy has vanished, reverify into
a new receipt; the old receipt alone does not validate a replacement or authorize
reading the original source payload. Workspace persistence remains a harness
property and must be checked; these settings cannot prevent external deletion.

## Next Actions

Each action should include:

- `stage`
- `reason`
- `expected_output`
- `stop_condition`
- exact `argv[]`

Execute `argv[]` as an argument vector, not through `sh -c`, `eval`, or string
concatenation. Review that the command remains `auto-re-cli`, static-only, and
within the current user request. Preserve input, architecture, raw-shellcode
context, and explicit analysis tuning.

Prefer the deterministic helper:

```bash
python3 scripts/run_next_action.py <result-json> \
  --action-stage <stage> \
  --output <new-output.json> \
  --receipt <receipts>/<stage>.json \
  --dry-run
```

Review the emitted `argv[]`, then remove `--dry-run` to launch the trusted
`auto-re-cli` binary with `shell=False`. The helper rejects a non-Auto-RE
program, `--execute`, inherited `--output`, parent-result overwrite, and a
missing output parent. Actions that already include `--bundle-dir` or
`--spill-dir` own their output sink and reject a caller-provided `--output`.

With `--receipt`, execution keeps only the final 1 MiB of each stdout/stderr
stream in separate read-only logs while hashing and counting the full streams.
The receipt records the exact resolved program, version, SHA-256, argv, sink,
times, exit code, byte counts, hashes, and truncation. These fields prove an
operational invocation boundary only; they are not target-analysis evidence.
Never mix stderr into an analysis JSON document.

Do not follow an action when:

- its evidence is irrelevant to the user's question;
- its stop condition is already satisfied;
- it would repeat the same non-progressing page or budget;
- it leaves static analysis;
- it targets an unverified path;
- the user did not authorize the required file write.

## Evidence Strength

Treat these as separate:

- **Validated:** an explicit validated/proven fact in the artifact.
- **Inferred:** a bounded heuristic, role, candidate, hint, or static
  interpretation with its confidence/reason.
- **Unresolved:** missing, ambiguous, unsupported, partial, truncated, or
  otherwise unproven.
- **Not claimed:** runtime behavior, source-grade semantics, complete ABI,
  complete devirtualization, or whole-program coverage unless explicitly
  validated.

Examples of evidence that must not be over-promoted:

- `display_name` does not replace the raw function identity.
- `why_interesting` explains ranking, not semantics.
- a source-shape marker is not reconstructed source code.
- a call graph is static and bounded, not runtime order or whole-program
  completeness.
- `data_to_code` is a static inverse view, not observed runtime access.
- recovered Go/Rust inventories do not prove source-grade recovery.
- UPX/VMProtect stages and candidates do not prove successful unpacking or
  devirtualization unless the explicit stage status says so.

## Citation Shape

Keep findings reproducible. Cite:

- input path and emitted input hash/identity;
- exact command and output path;
- manifest and section/payload path;
- function raw name and address;
- field names and status/reason/provenance;
- relevant warning, budget, truncation, or stop condition.

If evidence is absent from a bounded window, say "not present in the inspected
window", not "absent from the binary".

## Verified-Tree Cleanup

After the final consumer, remove only the validator-owned tree named by its
receipt:

```bash
python3 scripts/verify_bundle.py \
  --cleanup-receipt <receipts>/bundle-verification.json
```

Cleanup checks the receipt, private ownership marker, random token, stable root
identity, exact temporary-root containment, and validator prefix before deleting
the tree. Keep the bounded verification and cleanup summaries as audit evidence
when the user wants reproducibility.

## Retrospective And Conflicting Evidence

Keep historical reports separate from current analyzer output. Record each
artifact's input identity and tool version when available; missing commands,
versions, hashes or receipts remain missing. A filename such as `all_functions`
or a report heading such as "fully recovered" does not establish completeness.

Distinguish discovered functions, recovered names, analyzed bodies and emitted
rows. Read unresolved-edge counts and truncation alongside warnings. Empty
warnings and zero known callers do not establish complete or unreachable code.

When decoder versions disagree, retain the alternatives and the exact source
artifact/function/callsite. Require byte lengths, encoding and static transform
provenance before promoting a candidate. Strings alone do not prove endpoint
use, protocol behavior, maliciousness or attribution. User-supplied deployment
metadata must be labeled separately from binary-derived evidence.

## Request Identity And No Progress

For a new action, keep its execution receipt. Supported single-file requests add
`request_identity`: input bytes/hash, CLI hash and exact analysis arguments,
excluding output destinations. Identity is unavailable for unsupported command
shapes, nonregular/unstable files and inputs over 512 MiB; absence never means
identical. The receipt remains operational evidence, not a transform proof.

Pass `--prior-receipt <previous.json>` together with `--receipt <new.json>` to
`run_next_action.py` when continuing the same investigation. An identical
identity stops before analysis with `no_progress`, even if the output filename
changed. Compare the prior result's warnings and missing evidence before changing
a selector or budget. Changed inputs, CLI builds or budgets produce a new identity.
For durable output commitments and replay, use the existing `archive`/`replay`
commands and validated bundles; a request identity alone does not authenticate
old output bytes. Do not invent missing identities for historical scripts.
