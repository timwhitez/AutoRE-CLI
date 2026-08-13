# Command Routing

Load this reference when choosing a command instead of following an emitted
`next_actions[].argv`.

## Start Narrow

| Intent | Command | Preferred Agent output |
| --- | --- | --- |
| Initial bounded investigation | `report` | `--format json --json-profile ai --bundle-dir <dir>` |
| Fast binary metadata and discovery | `analyze` | `--format json --output <file>` |
| Compact pseudo and triage | `decompile` | `--format json --json-profile ai --limit <n>` |
| One known function | `function` | `--addr <pc> --format json` or `--symbol <name>` |
| Local region of a large function | `slice-function` | one of `--slice-index`, `--slice-start`, `--contains-call`, or `--contains-string` |
| LLIL/MLIL/HLIL/CUSTOM IL | `dump-il` | `--level <level> --addr <pc> --format json` |
| Basic blocks and successors | `dump-cfg` | one function selector plus `--format json` |
| Static root-centered flow | `inspect-flow` | bounded depth/node limits and JSON |
| Static call relationships | `call-graph` | `--json-profile ai` with node/edge budgets |
| Code/data or data/code references | `data-xrefs` | exact selector, direction, offset, limits, AI JSON |
| AArch64 formed-address evidence | `aarch64-refs` | exact selector and bounded AI JSON |
| PE resource tree | `pe-resources` | paged AI JSON |
| PE strings and references | `pe-strings` | paged AI JSON |
| Go build/runtime/function evidence | `inspect-go` | `--format json --json-profile ai` |
| Rust symbol/type/source context | `inspect-rust` | `--format json --json-profile ai` |
| Recovered type records | `inspect-types` | JSON |
| Structuring/printer pass status | `inspect-passes` | selected function plus JSON |
| Native byte fingerprints | `inspect-die` | `--format json --json-profile ai` |
| UPX stages and evidence | `inspect-upx` | `--format json --json-profile ai` |
| VMProtect stages/frontiers | `inspect-vmp` | `--format json --json-profile ai` |
| Experimental LLVM-oriented view | `dump-llvm` | selected function; never authoritative |
| Multiple samples | `batch` | explicit `--output-dir`, JSON, optional archives |
| Preserve/replay one result | `archive` / `replay` | JSON |
| Compare archived results | `diff` | JSON plus optional `--semantic-summary` |
| Replay/compare a batch | `batch-replay` / `batch-diff` | JSON |
| Measure the analyzer | `bench` | only for an explicit performance task |

Run `auto-re-cli <command> --help` before inventing an option. Do not pass
`--json-profile ai` to commands that do not support it.

## Selectors

- Use either `--addr` or `--symbol`, never both.
- Prefer an exact address emitted by Auto-RE over a guessed symbol spelling.
- Preserve the raw `name`; treat `display_name` as presentation only.
- For `slice-function`, choose exactly one local selector.
- Follow offsets and limits returned by pagination actions instead of widening
  all budgets.
- An address inside a function is not automatically the function start; retain
  the selected function identity returned by the wrapper.

## Input Context

For container-backed inputs, omit `--arch` unless a specific universal Mach-O
slice is required. Supported explicit analysis architectures are `x86`,
`x86_64`, and `aarch64`.

Raw shellcode requires all of:

```bash
--raw-shellcode --arch <arch> --base-address <address>
```

Add `--entry-address` only when known. Never infer raw architecture, base, or
entry from a filename. Preserve these flags in every generated follow-up.

## Budgets

Use the smallest budget that answers the question:

- `--max-functions`
- `--max-instructions-per-function`
- `--limit` and command-specific offsets
- flow depth/per-node/node limits
- call-graph node/edge limits
- record/provenance/instruction limits

When a result reports truncation, either follow its bounded continuation or
state the boundary. Do not silently rerun with unbounded or extreme values.

## Sinks

- One document: `--output <new-path>`.
- Direct compact-AI spill: `--spill-dir <new-dir>`.
- Report sections: `--bundle-dir <new-dir>`.
- Large text only when explicitly needed: `--split-output`.

Never reuse an input path as a sink. Never make a generated continuation
overwrite its parent result.
