# AutoRE-CLI

[English](README.md) | [简体中文](README_zh.md)

[![Validate Distribution](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml/badge.svg)](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

AutoRE-CLI is a binary-only distribution of Auto-RE: a CLI-first, static
reverse-engineering engine for human analysts and AI agents.

**Maintained and published independently by
[@timwhitez](https://github.com/timwhitez).**

This repository contains compiled binaries, the `auto-re` Skill, offline
installers, checksums, release provenance, third-party notices, and user
documentation. It does not publish the Rust source repository, private
specifications, samples, or analysis output.

[Install](#install) · [Agent Quick Start](#agent-quick-start) ·
[CLI Quick Start](#cli-quick-start) · [Platforms](#platforms) ·
[Verify](#integrity-and-provenance) · [Security](SECURITY.md)

## Highlights

- **Static-only safety:** never execute target bytes, recovered shellcode,
  unpacked payloads, embedded objects, or target-derived artifacts.
- **Agent-native output:** bounded JSON, explicit budgets, warnings, stop
  reasons, bundle/spill manifests, and executable `next_actions[].argv`.
- **Layered analysis:** disassembly, CFG, LLIL, MLIL, HLIL, CUSTOM IL, readable
  pseudo output, types, calls, and data references.
- **Language-aware evidence:** bounded Go and Rust inventories and proof states
  without pretending to recover source-grade semantics.
- **Malware-focused inspection:** PE resources/strings, static flow, packer and
  protection evidence, batch archives, replay, and semantic diffing.
- **Traceable releases:** every binary is bound to a source revision, byte
  count, target, signing disposition, and SHA-256.

## Install

Requirements:

- a supported macOS, Linux, or Windows host;
- Python 3.9 or newer;
- no Rust toolchain and no source checkout.

```sh
git clone https://github.com/timwhitez/AutoRE-CLI.git
cd AutoRE-CLI
./verify.sh
./install.sh
```

On Windows PowerShell, use the Python entrypoint (the `py -3` launcher or
`python` both work):

```powershell
git clone https://github.com/timwhitez/AutoRE-CLI.git
Set-Location AutoRE-CLI
py -3 scripts/autore_distribution.py verify
py -3 scripts/autore_distribution.py install
```

The default installation copies:

- `auto-re-cli` (or `auto-re-cli.exe` on Windows) to
  `${AUTORE_INSTALL_DIR:-$HOME/.local/bin}`;
- the Skill to `${TRAE_HOME:-$HOME/.trae}/skills/auto-re`;
- the Skill to `$HOME/.agents/skills/auto-re`.

The installer performs no network access. It verifies the complete
distribution before probing the selected binary, copies rather than symlinks,
uses managed markers, and refuses to overwrite unmanaged destinations unless
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

Ensure the binary directory is on `PATH`, then run:

```sh
auto-re-cli --version
```

### Update And Uninstall

Pull or extract a newer distribution, then rerun `./verify.sh` and
`./install.sh`. Managed drift, same-version repacks, downgrades, and extra Skill
files fail closed.

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

The Skill:

1. verifies `auto-re-cli`;
2. starts with a bounded AI JSON context bundle;
3. validates every bundle payload before reading it;
4. separates validated, inferred, unresolved, and not-claimed conclusions;
5. follows one relevant static continuation at a time;
6. stops on explicit stop conditions, sufficient evidence, exhausted budgets,
   or unsupported boundaries.

To prepare one emitted action without shell interpolation:

```sh
python3 skills/auto-re/scripts/run_next_action.py \
  ./analysis-results/sample.bundle/manifest.json \
  --action-id function.selected \
  --output ./analysis-results/function-selected.json \
  --dry-run
```

Remove `--dry-run` only after reviewing the validated argument vector. Actions
that already own a bundle/spill sink reject an additional `--output`.

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

- every `SHA256SUMS` row;
- all binary target/path/size/hash records in `manifest/release.json`;
- the exact managed Skill file set;
- the MIT-only project license boundary;
- the personal publisher and repository identity;
- absence of source roots, Rust source, private paths, samples, internal
  artifacts, and governed company/internal-account markers.

`manifest/release.json` records the publisher, repository URL, release version,
source revision, toolchain, target matrix, and static-safety flags.
`THIRD_PARTY_LICENSES.md` and `licenses/third-party/` preserve dependency
notices separately from the project license.

## Repository Layout

```text
bin/                         platform binaries
skills/auto-re/              agent Skill and deterministic helpers
scripts/autore_distribution.py
manifest/release.json        machine-readable provenance
licenses/third-party/        dependency notices
SHA256SUMS                   outer integrity manifest
install.sh / uninstall.sh    managed local installation
verify.sh                    fail-closed distribution verifier
```

## Support

- Bugs and documentation:
  [issue tracker](https://github.com/timwhitez/AutoRE-CLI/issues)
- Security:
  [private vulnerability report](https://github.com/timwhitez/AutoRE-CLI/security/advisories/new)
- Contribution boundary: [CONTRIBUTING.md](CONTRIBUTING.md)
- Maintainer: [@timwhitez](https://github.com/timwhitez)

Do not upload malware samples, recovered payloads, secrets, private paths, or
proprietary analysis output.

## License

AutoRE-CLI is licensed under the [MIT License](LICENSE-MIT).
Third-party dependencies retain their own licenses, including Apache-licensed
dependencies where applicable; see
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
