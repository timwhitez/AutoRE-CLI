# Optional compact AI evidence view v1

Use `compact_result.py` only to reduce context from an existing report/decompile
AI JSON file. This offline checkout helper performs no analysis, model call or
CLI upgrade. Prefer existing sections, paging, selected scope, spill and bundles
when they already answer the question.

```sh
python3 <skill-dir>/scripts/compact_result.py <retained-ai.json> \
  --expected-sha256 <original-sha256> > <new-view.json>
```

Choose a fresh output file and retain the original. The input uses the existing
stable-file, no-symlink, 64 MiB reader policy and its JSON shape limits. A changed
hash stops with `source_changed`; unsupported versions/profiles/roots fail closed.
The helper writes normalized JSON to stdout and never modifies its source.
Source float numerals remain exact, including underflow and signed zero, in both
compact and full fallback output. Float overflow follows the shared reader's
existing `invalid_json_or_structure` rejection (for example, `1e400`).

Compaction activates only when the complete new document, including its locator
and catalog, saves at least 10% and 1 KiB against normalized original JSON.
The completed candidate must also satisfy the shared reader's byte, depth,
value-count, container-entry and string-byte limits. Otherwise it returns the
complete normalized original, with every field intact. Reference insertion that
would exceed the depth limit therefore falls back safely.
This is a compatibility gate, not a model token claim. No CLI profile changes.

A compact result has `kind=auto_re_compact_ai_view`, `schema_version=0.1.0` and
integer `compact_version=1`. Exact repeated hint objects, nested hint
`field_states`, semantic summaries and pass rows are stored once in `catalog`.
Single-member `{"$agent_ref":N}` objects reference that flat catalog. Each owner
address and array position remains in place; raw/display names, pseudo, scope,
counts, warnings, budgets, completion/stop controls and continuations survive.
All Applied/Skipped/unknown statuses and applicability notes remain retrievable
inline. No field is promoted to proven source semantics or runtime behavior.

`full_view.artifact`, `bytes` and `sha256` identify the untouched original.
Here full means the original selected AI document, not whole-program coverage
or the core full-profile artifact. Read a catalog entry with the existing bounded
reader, or read the original with its expected digest:

```sh
python3 <skill-dir>/scripts/read_result.py <new-view.json> --pointer /catalog/0
python3 <skill-dir>/scripts/read_result.py <original-path> \
  --expected-sha256 <full-view-sha256> --pointer /functions/0/address
```

Views grant no semantic admission. **Do not pass a compact result to
`run_next_action.py`**: C1 rejects its exact kind as `unsupported_result_kind`.
Verify and use the original result for continuations. A finished page, empty
warnings or successful process never establishes complete analysis. The generic
reader may return `boundary_too_large` even for a small leaf; a verified original
host read remains valid. Use v2 `string` pages for a large individual string.
