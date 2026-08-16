# AutoRE-CLI

[English](README.md) | [简体中文](README_zh.md)

[![Validate Distribution](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml/badge.svg)](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml)
[![Release](https://img.shields.io/github/v/release/timwhitez/AutoRE-CLI?display_name=tag)](https://github.com/timwhitez/AutoRE-CLI/releases/latest)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-64748b)](#platforms)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

**Bounded static reverse engineering for human analysts and AI agents.**

AutoRE-CLI turns ELF, PE/COFF, Mach-O, object files, and explicitly identified
raw shellcode into traceable JSON, CFG/IL, readable pseudo output, language
evidence, and safe next actions—without executing target bytes.

![AutoRE-CLI controlled static analysis demo](assets/demo.png)

[Download](https://github.com/timwhitez/AutoRE-CLI/releases/latest) ·
[Agent Quick Start](#agent-quick-start) · [CLI Quick Start](#cli-quick-start) ·
[Why AutoRE-CLI](#why-autore-cli) · [Security](SECURITY.md) · [FAQ](FAQ.md)

## Why AutoRE-CLI

- **Evidence before confidence:** findings remain explicitly `validated`,
  `inferred`, `unresolved`, or `not_claimed`.
- **Agent-sized context:** bounded JSON, budgets, warnings, stop reasons,
  verified bundles, and exact `next_actions[].argv` prevent output floods.
- **Static-only boundary:** no target, recovered payload, shellcode, embedded
  object, or target-derived artifact is executed.
- **Layered inspection:** disassembly, CFG, LLIL, MLIL, HLIL, CUSTOM IL, pseudo
  output, types, calls, data references, PE inventories, and Go/Rust evidence.
- **Repeatable investigations:** archive, replay, semantic diff, and batch
  comparison preserve the evidence path.
- **Offline and traceable:** installation performs no network access; every
  release binary has an exact target, byte count, source revision, signing
  disposition, and SHA-256.

### Where It Fits

| Tool | Best fit | AutoRE-CLI difference |
| --- | --- | --- |
| Ghidra, Rizin, angr | Extensible interactive frameworks and custom analysis | AutoRE-CLI is a prebuilt, CLI-first bounded evidence surface for automation and agents |
| Ghidra MCP integrations | Conversational control of an existing Ghidra environment | AutoRE-CLI needs no GUI or analysis server and keeps static-only limits in the output contract |
| capa | Rule-based capability identification | AutoRE-CLI exposes functions, CFG/IL, pseudo output, references, language evidence, and comparison workflows |
| General binary-analysis Skills | Methodology layered over separately installed tools | The included Skill and CLI share one verified action, artifact, and evidence contract |

AutoRE-CLI is not a debugger, emulator, sandbox, or claim of perfect source
recovery. Use the larger frameworks when you need plugins, interactive GUI
workflows, symbolic execution, or dynamic observation.

## Install

Requirements: Python 3.9 or newer and a supported host. No Rust toolchain or
source checkout is required.

### Platform Release

Download the archive for your host from
[GitHub Releases](https://github.com/timwhitez/AutoRE-CLI/releases/latest),
then verify and install it:

```sh
tar -xzf AutoRE-CLI-0.1.1-macos-arm64.tar.gz
cd AutoRE-CLI-0.1.1-macos-arm64
./verify.sh
./install.sh
auto-re-cli --version
```

Replace `macos-arm64` with `macos-x86_64`, `linux-x86_64`, or `linux-arm64`.
Windows users should extract `AutoRE-CLI-0.1.1-windows-x86_64.zip` and run:

```powershell
py -3 scripts/autore_distribution.py verify
py -3 scripts/autore_distribution.py install
auto-re-cli --version
```

Each approximately 7–8 MB platform archive contains one binary, the Agent
Skill, offline installers, provenance, checksums, and notices. You can also
clone this repository to obtain the complete platform matrix:

```sh
git clone --depth 1 https://github.com/timwhitez/AutoRE-CLI.git
cd AutoRE-CLI
./verify.sh
./install.sh
```

### Package Managers

Package managers install the CLI only. Install the Agent Skill separately, or
use the platform archive above for the complete verified distribution.

```sh
# Agent Skill for Codex, Claude Code, Cursor, and other supported clients
npx skills add \
  https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.1/AutoRE-CLI-0.1.1-auto-re-skill.zip -g
```

```powershell
# Scoop CLI on Windows
scoop install https://raw.githubusercontent.com/timwhitez/AutoRE-CLI/main/packaging/scoop/autore-cli.json
```

The repository includes the versioned
[Homebrew formula](https://github.com/timwhitez/AutoRE-CLI/blob/main/packaging/homebrew/autore-cli.rb)
and
[Scoop manifest](https://github.com/timwhitez/AutoRE-CLI/blob/main/packaging/scoop/autore-cli.json).
The Homebrew formula is ready for a dedicated Tap; until that Tap is published,
use the verified macOS or Linux platform archive. Package-manager availability
can lag behind a GitHub Release.

The default installation copies:

- `auto-re-cli` (or `auto-re-cli.exe`) to
  `${AUTORE_INSTALL_DIR:-$HOME/.local/bin}`;
- the Skill to `${TRAE_HOME:-$HOME/.trae}/skills/auto-re`;
- the Skill to `$HOME/.agents/skills/auto-re`.

The installer verifies the complete extracted distribution, probes only the
verified binary with `--version`, copies rather than symlinks, records managed
markers, and refuses to overwrite unmanaged destinations unless
`--replace-unmanaged` is explicit.

Common options:

```sh
./install.sh --dry-run
./install.sh --cli-only
./install.sh --skill-only --agents trae
./install.sh --skill-only --agents codex
./install.sh --skill-only --agents both
./install.sh --install-dir "$HOME/bin"
./install.sh --skill-only --agents codex --codex-home "$HOME/.codex"
```

`--codex-home` selects the legacy `<home>/skills` compatibility location. The
current default is `$HOME/.agents/skills`.

### Update And Uninstall

Extract a newer release, then rerun `./verify.sh` and `./install.sh`. Managed
drift, same-version binary repacks, downgrades, and extra Skill files fail
closed.

```sh
./uninstall.sh
./uninstall.sh --force-managed
```

`--force-managed` applies only to marker-listed files whose content changed.
It never authorizes removal of unrelated parent directories or extra user
files.

## Agent Quick Start

Restart or refresh your agent after installation, then invoke:

```text
Use $auto-re to statically inspect ./sample.exe and write bounded,
evidence-backed findings under ./analysis-results. Never execute the sample or
any target-derived artifact.
```

The Skill verifies the CLI, validates bundle ownership/size/SHA-256 before
reading payloads, separates evidence strength, follows one relevant static
continuation at a time, and stops at explicit evidence or budget boundaries.

To prepare one emitted action without shell interpolation:

```sh
python3 skills/auto-re/scripts/run_next_action.py \
  ./analysis-results/sample.bundle/manifest.json \
  --action-stage function.selected \
  --output ./analysis-results/function-selected.json \
  --dry-run
```

Review the exact argument vector before removing `--dry-run`. Actions that
already own a bundle/spill sink reject an additional `--output`.

## CLI Quick Start

### Bounded Context Bundle

```sh
mkdir -p ./analysis-results
auto-re-cli report ./sample.exe \
  --format json \
  --json-profile ai \
  --sections binary,summary,inspections,flow,functions,types \
  --limit 8 \
  --bundle-dir ./analysis-results/sample.bundle \
  --output ./analysis-results/sample.bundle/manifest.json

python3 skills/auto-re/scripts/verify_bundle.py \
  ./analysis-results/sample.bundle/manifest.json
```

The manifest records owned payload paths, byte counts, SHA-256, warnings,
budgets, completion state, current findings, and bounded next actions.

### Focused Function

```sh
auto-re-cli function ./sample.exe \
  --addr 0x401000 \
  --format json \
  --output ./analysis-results/function-401000.json

auto-re-cli dump-il ./sample.exe \
  --level custom \
  --addr 0x401000 \
  --format json \
  --output ./analysis-results/custom-il-401000.json
```

### Reproduce The Safe Demo

[`examples/controlled/fixture.c`](examples/controlled/fixture.c) is a benign,
independently authored fixture. Build it as a non-runnable object and follow
the commands in
[`examples/controlled/README.md`](examples/controlled/README.md). The checked
demo found one AArch64 function, completed without truncation or warnings, and
kept absent type evidence as `not_claimed`.

### Explicit Raw Shellcode

```sh
auto-re-cli report ./stage.bin \
  --raw-shellcode \
  --arch x86 \
  --base-address 0x1000 \
  --entry-address 0x1000 \
  --format json \
  --json-profile ai \
  --sections summary,flow,functions \
  --bundle-dir ./analysis-results/raw.bundle \
  --output ./analysis-results/raw.bundle/manifest.json
```

Raw architecture, base, and entry are caller-provided facts. Never guess them
from a filename.

## Analysis Surfaces

| Task | Command |
| --- | --- |
| Aggregate triage | `report`, `analyze`, `decompile` |
| Function and local slices | `function`, `slice-function` |
| Intermediate language and CFG | `dump-il`, `dump-cfg`, `inspect-passes` |
| Static relationships | `inspect-flow`, `call-graph`, `data-xrefs`, `aarch64-refs` |
| PE inventories | `pe-resources`, `pe-strings` |
| Language evidence | `inspect-go`, `inspect-rust`, `inspect-types` |
| Protection evidence | `inspect-die`, `inspect-upx`, `inspect-vmp` |
| Repeatable comparison | `batch`, `archive`, `replay`, `diff`, `batch-diff` |

Run `auto-re-cli <command> --help` for the exact options supported by the
installed version.

## Platforms

| Host | Release target | Status |
| --- | --- | --- |
| macOS Apple Silicon | `macos-arm64` | Published; ad-hoc signed |
| macOS Intel | `macos-x86_64` | Published; ad-hoc signed |
| Linux x86-64 | `linux-x86_64` | Published |
| Linux AArch64 | `linux-arm64` | Published |
| Windows x86-64 | `windows-x86_64` | Published; unsigned |

The macOS binaries are not Developer ID signed or notarized. The Windows
binary supports Windows 10 or newer and is not Authenticode signed.

## Integrity And Provenance

Run `./verify.sh` before installation. It validates:

- every `SHA256SUMS` row and exact public file set;
- every binary target/path/size/hash in `manifest/release.json`;
- the exact managed Skill file set;
- the MIT-only project license boundary;
- the personal publisher and repository identity;
- absence of source roots, Rust source, private paths, samples, internal
  artifacts, and governed internal-account markers.

`manifest/release.json` records the publisher, repository URL, release version,
distribution scope, source revision, toolchain, target matrix, and static
safety flags. `THIRD_PARTY_LICENSES.md` and `licenses/third-party/` preserve
dependency notices separately from the project license.

## Public Repository Boundary

This repository is the MIT-licensed **public binary distribution** of Auto-RE.
It contains compiled binaries, the open Agent Skill and helpers, installers,
verifier, release automation, controlled demo source, checksums, provenance,
notices, and documentation.

The engine's Rust implementation, private specifications, samples, and
analysis output are not published here. “Open source” in this repository
applies to the public scripts, Skill, examples, automation, and documentation;
it does not imply that the binary engine implementation is available.

## Repository Layout

```text
assets/                       public demo and social artwork
bin/                          platform binaries
examples/controlled/          benign reproducible demo source
skills/auto-re/               Agent Skill and deterministic helpers
scripts/autore_distribution.py
scripts/build_release_assets.py
manifest/release.json         machine-readable provenance
licenses/third-party/         dependency notices
SHA256SUMS                    outer integrity manifest
install.sh / uninstall.sh     managed local installation
verify.sh                     fail-closed distribution verifier
```

## Support

- Bugs and documentation:
  [issue tracker](https://github.com/timwhitez/AutoRE-CLI/issues)
- Use cases and integration requests:
  [public discussion](https://github.com/timwhitez/AutoRE-CLI/discussions/1)
- Security:
  [private vulnerability report](https://github.com/timwhitez/AutoRE-CLI/security/advisories/new)
- Contribution boundary: [CONTRIBUTING.md](CONTRIBUTING.md)
- Release history: [CHANGELOG.md](CHANGELOG.md)
- Maintainer: [@timwhitez](https://github.com/timwhitez)

Do not upload malware samples, recovered payloads, secrets, private paths, or
proprietary analysis output.

## License

The public AutoRE-CLI distribution is licensed under the
[MIT License](LICENSE-MIT). Third-party dependencies retain their own licenses,
including Apache-licensed dependencies where applicable; see
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
