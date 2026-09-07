# Changelog

All notable changes to the public AutoRE-CLI distribution are recorded here.

## [Unreleased]

## [0.1.5] - 2026-09-07

- Rebuilt all five platform binaries locally from `158ca044a1908e9ae2b39105d68ccbd4b333bc51`.
- Added bounded Go inventory fallback, formed-address indirect call discovery,
  explicit AArch64 memory effects and static byte candidates.
- Updated checkout diagnosis, no-progress receipts and investigation guidance.
- See [release notes](release-notes/v0.1.5.md) for validation and capability limits.

## [0.1.4] - 2026-09-05

- See the [0.1.4 release notes](release-notes/v0.1.4.md) for the locally rebuilt
  matrix and parser, LLVM, lifecycle and packaging changes.

## [0.1.3] - 2026-09-01

### Added

- Versioned Auto-RE Skill metadata, trigger-boundary evaluations, and a
  read-only doctor for CLI/Skill version agreement, managed-content drift, and
  duplicate registration.
- Versioned bundle verification and action execution receipts with bounded
  stdout/stderr tails, full-stream hashes, and explicit cleanup ownership.

### Changed

- Rebuilt all five platform binaries from source revision
  `253dcdf0c6834bd04af63e4ecaa45e6f5cf96d76` with Rust 1.97.1.
- Routes explicit function, CFG/IL, reference, PE, language, protection, replay,
  and diff questions through the smallest matching static command before
  open-ended report generation.
- Updated the Skill prompt, platform invocation guidance, installers, verifier,
  provenance manifest, and third-party dependency inventory.

### Security

- Rejects oversized bundle cardinality and aggregate payload declarations
  before materialization, and rejects an opened payload size mismatch before
  reading or creating its verified destination.
- Binds verified-tree cleanup to a private marker, random token, stable root
  identity, and the system temporary directory.

## [0.1.2] - 2026-08-31

### Added

- Exact repository and one-platform distribution scopes for independently
  verifiable release archives.
- Static recovery for additional ELF PLT, PE import, DWARF, AArch64, x86, Go,
  and Rust evidence families.

### Changed

- Rebuilt all five platform binaries from source revision
  `35380fa076394ff4f63bb6ab0665bc58d18bcd04` with Rust 1.97.1.
- Updated the Agent Skill, bounded continuation helpers, installer, verifier,
  provenance manifest, and third-party dependency inventory.

### Security

- Hardened archive path identity, artifact transactions, split-output
  ownership, bounded control-file reads, streaming hashes, XAR/CPIO integrity,
  and trusted UPX helper launch handling.

## [0.1.1] - 2026-08-17

### Added

- Reproducible controlled object-file demo and terminal-style visual.
- Explicit project comparison and public-repository boundary documentation.
- FAQ in English and Simplified Chinese.
- Deterministic, independently verifiable per-platform release archives.
- Release automation, notes, and multi-channel launch copy.
- Windows x86-64 binary and validation workflow.
- Current `$HOME/.agents/skills` installation path with legacy Codex
  compatibility.

### Changed

- Reworked the English and Chinese README front pages around value, evidence,
  demonstration, installation, and trust.
- Extended the verifier to recognize complete repository distributions and
  one-target platform distributions without weakening binary or Skill checks.
- Rebuilt all five platform binaries from source revision
  `abca804d5773b055c29fccbc52f8d2a2e83517cb`.
- Preserved checksum bytes on Windows checkouts.

## [0.1.0] - 2026-08-13

### Added

- Initial public binary distribution for macOS arm64/x86-64 and Linux
  arm64/x86-64.
- Offline installer, uninstaller, fail-closed verifier, release provenance,
  third-party notices, and `auto-re` Agent Skill.

[Unreleased]: https://github.com/timwhitez/AutoRE-CLI/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/timwhitez/AutoRE-CLI/releases/tag/v0.1.3
[0.1.2]: https://github.com/timwhitez/AutoRE-CLI/releases/tag/v0.1.2
[0.1.1]: https://github.com/timwhitez/AutoRE-CLI/releases/tag/v0.1.1
[0.1.0]: https://github.com/timwhitez/AutoRE-CLI/releases/tag/v0.1.0
