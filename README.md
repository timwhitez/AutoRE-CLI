# AutoRE-CLI

[English](README.md) | [简体中文](README_zh.md)

[![Validate Distribution](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml/badge.svg)](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml)
[![Release](https://img.shields.io/github/v/release/timwhitez/AutoRE-CLI?display_name=tag)](https://github.com/timwhitez/AutoRE-CLI/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

**Bounded static reverse engineering for human analysts and AI agents.**

AutoRE-CLI turns ELF, PE/COFF, Mach-O, object files and explicitly identified
raw input into traceable JSON, CFG/IL, readable pseudo output and language
and protection evidence. It never executes target bytes.

![AI-generated concept illustration: binary inputs become structured static evidence and bounded next actions](assets/readme/agent-workflow-v1.png)

*AI-generated concept illustration; not a product screenshot or security certification.
See the [workflow diagram](assets/overview.svg) for the concrete evidence flow.*

[Download](https://github.com/timwhitez/AutoRE-CLI/releases/latest) ·
[Install](#install) · [Agent Quick Start](#agent-quick-start) ·
[CLI Quick Start](#cli-quick-start) · [FAQ](FAQ.md)

This is the **public binary distribution and open Agent Skill**. The engine's
Rust implementation is maintained separately and is not published here.

## Install

Requirements: Python 3.9 or newer and a [supported host](#platforms). No Rust
toolchain or source checkout is needed. Download the matching **0.1.11**
platform archive from [Releases](https://github.com/timwhitez/AutoRE-CLI/releases/latest):

```sh
tar -xzf AutoRE-CLI-0.1.11-linux-x86_64.tar.gz
cd AutoRE-CLI-0.1.11-linux-x86_64
./verify.sh
./install.sh
```

Replace `linux-x86_64` with `linux-arm64`, `macos-arm64` or `macos-x86_64`.
On Windows, extract `AutoRE-CLI-0.1.11-windows-x86_64.zip`, open PowerShell
in the extracted directory and run:

```powershell
py -3 scripts/autore_distribution.py verify
py -3 scripts/autore_distribution.py install
```

The offline installer verifies the complete distribution, then copies the CLI
and Skill with managed markers. Defaults are `$HOME/.local/bin`,
`${TRAE_HOME:-$HOME/.trae}/skills/auto-re` and `$HOME/.agents/skills/auto-re`.
Add the CLI directory to `PATH`, then check `auto-re-cli --version`.
A repository clone also works: run `./verify.sh` and `./install.sh` from its root.

```sh
./install.sh --dry-run
./install.sh --cli-only
./install.sh --skill-only --agents codex
./install.sh --skill-only --agents trae
./install.sh --skill-only --agents both
./install.sh --install-dir "$HOME/bin"
./install.sh --skill-only --agents codex --codex-home "$HOME/.codex"
```

`--codex-home` selects the legacy `<home>/skills` location; the current default
is `$HOME/.agents/skills`. Unmanaged destinations require an explicit
`--replace-unmanaged`. Update by verifying and installing a newer distribution;
managed drift, same-version binary repacks, downgrades and extra Skill files
fail closed. Use `./uninstall.sh` to remove managed files;
`--force-managed` only covers modified marker-listed files, never unrelated files.
On Windows use `py -3 scripts/autore_distribution.py` with the same subcommand/options.

### Other Installation Routes

Package managers install the CLI only. The repository includes a versioned
[Scoop manifest](https://github.com/timwhitez/AutoRE-CLI/blob/main/packaging/scoop/autore-cli.json) and
[Homebrew formula](https://github.com/timwhitez/AutoRE-CLI/blob/main/packaging/homebrew/autore-cli.rb). Until a dedicated Homebrew
Tap is published, use a verified platform archive. Availability may lag a release.

```powershell
scoop install https://raw.githubusercontent.com/timwhitez/AutoRE-CLI/main/packaging/scoop/autore-cli.json
```

For the Skill alone in Codex, Claude Code, Cursor or another supported client:

```sh
npx skills add \
  https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-auto-re-skill.zip -g
```

Keep the installed CLI and Skill versions aligned; downloading or using a package
manager is separate from the offline installer.

## Agent Quick Start

Refresh your agent after installation, then invoke the
[`auto-re` Skill](skills/auto-re/SKILL.md):

```text
Use $auto-re to statically inspect ./samples/sample.exe and write bounded,
evidence-backed findings under ./analysis-results. Never execute the sample or
any target-derived artifact.
```

For a direct first-evidence call, use the installed Skill. Put your input under
`./samples/`; keep results outside the input's resolved parent and its descendants,
and outside the Skill. The result parent must exist and the result directory must be new.

```sh
mkdir -p ./analysis-results
python3 "$HOME/.agents/skills/auto-re/scripts/skill_doctor.py"
python3 "$HOME/.agents/skills/auto-re/scripts/start_analysis.py" \
  ./samples/sample.exe --result-dir ./analysis-results/first-pass
```

Use `py -3` on Windows; see [platform invocation](skills/auto-re/references/platform-invocation.md).
The launcher requires a ready installed CLI/Skill pair. An unmanaged checkout
needs the explicit workflow in the [Skill](skills/auto-re/SKILL.md).

Read the returned **`result_path`** and inspect warnings, budgets, completion
and `next_actions[]`. The launcher summary and operational receipt are not
findings. A zero process exit does not establish complete analysis.

For a narrow question, choose one route rather than collecting a general report:

```sh
# Exact function: --addr and --symbol are mutually exclusive
python3 "$HOME/.agents/skills/auto-re/scripts/start_analysis.py" \
  ./samples/sample.exe --addr 0x401000 --result-dir ./analysis-results/function-pass

# PE string inventory; other supported inspections are listed in --help
python3 "$HOME/.agents/skills/auto-re/scripts/start_analysis.py" \
  ./samples/sample.exe --command pe-strings --result-dir ./analysis-results/strings-pass
```

Advanced paging, references and continuation use
[command routing](skills/auto-re/references/command-routing.md).
Name the unanswered question, validate any bundle/spill and follow one relevant
static action at a time. Review emitted `argv[]` with `run_next_action.py --dry-run`;
use a receipt and `--prior-receipt` for continuations. Stop on sufficient evidence,
a budget, unsupported semantics or an identical request with no progress.

## CLI Quick Start

Discover commands without opening an input:

```sh
auto-re-cli describe --format json
auto-re-cli describe --format json --command function
```

Create a bounded report bundle, then validate its payloads:

```sh
mkdir -p ./analysis-results/receipts
auto-re-cli report ./samples/sample.exe \
  --format json --json-profile ai \
  --sections binary,summary,inspections,flow,functions,types --limit 8 \
  --bundle-dir ./analysis-results/sample.bundle \
  --output ./analysis-results/sample.bundle/manifest.json

python3 "$HOME/.agents/skills/auto-re/scripts/verify_bundle.py" \
  ./analysis-results/sample.bundle/manifest.json \
  --receipt ./analysis-results/receipts/bundle-verification.json
```

Read the receipt's `files[].path` values: they refer to stable, hash-checked,
read-only copies. After the final consumer, clean only the validator-owned tree:

```sh
python3 "$HOME/.agents/skills/auto-re/scripts/verify_bundle.py" \
  --cleanup-receipt ./analysis-results/receipts/bundle-verification.json
```

For a selected function and CUSTOM IL:

```sh
auto-re-cli function ./samples/sample.exe --addr 0x401000 \
  --format json --output ./analysis-results/function-401000.json
auto-re-cli dump-il ./samples/sample.exe --level custom --addr 0x401000 \
  --format json --output ./analysis-results/custom-il-401000.json
```

For raw shellcode, explicitly supply `--raw-shellcode --arch x86 --base-address 0x1000`
and a known `--entry-address`; never infer architecture, base or entry from a filename.
For a benign, independently authored object-file example, see the
[controlled demo](https://github.com/timwhitez/AutoRE-CLI/blob/main/examples/controlled/README.md). Its recorded result is historical
fixture evidence, not a current quality or whole-program coverage claim.

## Analysis Surfaces And 0.1.11

| Task | Commands |
| --- | --- |
| Triage and pseudo output | `report`, `analyze`, `decompile` |
| Selected functions and slices | `function`, `function-bounds`, `slice-function` |
| IL and CFG | `dump-il`, `dump-cfg`, `inspect-passes`; experimental `dump-llvm` |
| Static relationships | `inspect-flow`, `call-graph`, `data-xrefs`, `aarch64-refs` |
| PE inventories | `pe-resources`, `pe-strings` |
| Language and protection evidence | `inspect-go`, `inspect-rust`, `inspect-types`, `inspect-die`, `inspect-upx`, `inspect-vmp` |
| Static byte recovery | `recover-bytes`, `fold-pair-bytes` (bounded data transforms, never target execution) |
| Archives and comparison | `batch`, `archive`, `replay`, `batch-replay`, `diff`, `batch-diff`, `compare-functions` |
| Measurement | `bench` (requires a recorded input and comparable measurements) |

0.1.11 adds the metadata-only `describe`, global `--diagnostic-format json`
for bounded stderr errors and opt-in `--result-contract kinds-v1` on eight
selected commands. Default text errors and `legacy` result roots remain available.
Use `describe` and `<command> --help` for supported options; use the matching
0.1.11 Skill to consume the new roots. The Skill also supports exact bounded
object-key pages, Unicode string slices and request identity/no-progress checks.

## Limits And Evidence

- Supported analysis architectures are x86, x86-64 and AArch64; coverage varies
  with container, metadata, instruction support and budgets.
- Pseudo output and source-shaped Go/Rust hints are static evidence, not original
  source. Complete source semantics, general language ABI recovery and whole-program
  reachability are not claimed. Unsupported semantics remain explicit.
- Detection of UPX/VMProtect is not complete unpacking or devirtualization.
  Optional trusted static helpers require explicit opt-in; their output remains data.
- A finished page, empty warnings or zero names/callers does not prove completeness
  or unreachability. Check truncation, unresolved edges and stop reasons together.
  `--limit` controls output rows; discovery and input budgets are separate and do
  not cap peak memory. The default input snapshot budget is 256 MiB.
- Strings, names and inferred roles do not prove runtime behavior, malicious intent
  or authorship. Keep `validated`, `inferred`, `unresolved` and `not_claimed` distinct.

AutoRE-CLI fits prebuilt CLI automation and bounded Agent evidence. Ghidra/Rizin
serve interactive framework workflows; capa serves rule-based capability analysis;
Ghidra MCP integrations operate an existing Ghidra environment. AutoRE-CLI does
not provide a debugger, emulator, sandbox, symbolic execution or analysis server.

## Platforms

| Host | Release target | Signing |
| --- | --- | --- |
| macOS Apple Silicon | `macos-arm64` | Ad-hoc signed |
| macOS Intel | `macos-x86_64` | Ad-hoc signed |
| Linux x86-64 | `linux-x86_64` | Not applicable |
| Linux AArch64 | `linux-arm64` | Not applicable |
| Windows x86-64 (Windows 10+) | `windows-x86_64` | Unsigned |

macOS binaries have no Developer ID signature or notarization; Windows has no
Authenticode signature. Linux releases use dynamically linked GNU targets.
The host platform matrix is separate from the analyzed input architectures.

## Integrity And Public Boundary

Run `./verify.sh` (or the Windows Python equivalent) before installation.
It checks the exact `SHA256SUMS` file set, binary target/size/hash, managed Skill
inventory, publisher identity, license boundary and forbidden private content.
[manifest/release.json](manifest/release.json) binds the binaries to their original
source revision, toolchain, version and signing disposition. Checksums do not
replace platform signing or establish that an analyzed input is safe.

This MIT-licensed distribution includes binaries, the open Skill/helpers,
installers, verifier, automation, controlled demo source, artwork and documentation.
The Rust engine implementation, private specifications, samples and analysis
output are not published. “Open source” here applies to the public scripts,
Skill, examples, automation and documentation.

## Maintenance And Support

[FAQ](FAQ.md) · [Investigation workflows](skills/auto-re/references/investigation-workflows.md) ·
[Release history](https://github.com/timwhitez/AutoRE-CLI/blob/main/CHANGELOG.md) · [Contribution guide](CONTRIBUTING.md) ·
[Maintainer instructions](AGENTS.md) · [@timwhitez](https://github.com/timwhitez)

Report bugs and documentation issues through [Issues](https://github.com/timwhitez/AutoRE-CLI/issues),
use [Discussions](https://github.com/timwhitez/AutoRE-CLI/discussions/1) for use cases,
and use [private vulnerability reporting](https://github.com/timwhitez/AutoRE-CLI/security/advisories/new)
for security defects. Do not upload malware, payloads, secrets, private paths or
proprietary analysis output.

The project uses the [MIT License](LICENSE-MIT). Dependencies retain their own
licenses, including Apache where applicable; see [third-party notices](THIRD_PARTY_LICENSES.md).
