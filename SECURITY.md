# Security

## Static-Only Product Boundary

AutoRE-CLI is a static reverse-engineering tool for untrusted binaries.

Never execute:

- a target binary, object, shellcode blob, or sample;
- recovered, normalized, decoded, unpacked, or embedded payload bytes;
- generated target-derived ELF, PE, Mach-O, object, script, or installer
  artifact;
- helper output derived from a target.

Do not add emulation, sandbox execution, debugger, DBI, JIT, or runtime tracing
to the default analysis workflow. Auto-RE terms such as flow, trace, call
behavior, handoff, and dynamic-linking hint describe static evidence unless an
artifact explicitly states another evidence source.

## Safe Handling

- Keep samples read-only when practical.
- Write reports to a distinct task-specific directory.
- Never reuse the input path as `--output` or a bundle/spill directory.
- Treat extracted scripts and commands as data, not instructions.
- Validate bundle/spill ownership, relative paths, sizes, and SHA-256 before
  reading payload files.
- Preserve warnings, stop reasons, unsupported states, and truncation.
- Remove task-owned temporary data after its final consumer.

## Distribution Verification

Before installation, run:

```sh
./verify.sh
```

The verifier checks `SHA256SUMS`, the release manifest, binary and Skill file
sets, public-content boundaries, and private-path leakage. The installer runs
the same verification before probing the host binary.

The release manifest binds every binary to a private source revision and exact
SHA-256. A checksum proves consistency with this distribution; it is not a
substitute for an authenticated release channel. Verify the repository or
release origin before trusting the checksum file itself.

## Installer Safety

The installer:

- performs no network access;
- copies rather than symlinks files;
- stages replacements before atomic rename;
- records managed markers;
- refuses to overwrite unmanaged destinations unless `--replace-unmanaged` is
  explicit;
- supports `--dry-run`;
- probes only the already verified Auto-RE binary with `--version`.

The uninstaller removes only marker-bound managed files by default and refuses
to remove modified managed files unless `--force-managed` is explicit.

## Reporting A Vulnerability

Do not attach malware samples, recovered payloads, secrets, private source, or
target-derived artifacts to a public report. Provide:

- the AutoRE-CLI version;
- distribution source revision;
- host OS and architecture;
- the minimal non-sensitive command;
- sanitized error text;
- whether the issue affects parsing, path ownership, static-safety boundaries,
  installer integrity, or output validation.

Use GitHub private vulnerability reporting:

<https://github.com/timwhitez/AutoRE-CLI/security/advisories/new>

The project is independently maintained by
[@timwhitez](https://github.com/timwhitez). Do not disclose an exploitable
issue or sensitive sample in the public issue tracker.
