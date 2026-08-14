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

Use `scripts/verify_bundle.py <manifest>` for this check. Its JSON result lists
the validated files. Do not infer trust from the directory name.

`spill_summary.manifest_path` is only a pointer. Validate the referenced
manifest before loading the complete payload.

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
  --dry-run
```

Review the emitted `argv[]`, then remove `--dry-run` to launch the trusted
`auto-re-cli` binary with `shell=False`. The helper rejects a non-Auto-RE
program, `--execute`, inherited `--output`, parent-result overwrite, and a
missing output parent. Actions that already include `--bundle-dir` or
`--spill-dir` own their output sink and reject a caller-provided `--output`.

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
