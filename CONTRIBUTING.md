# Contributing

AutoRE-CLI is a binary-only distribution maintained by
[@timwhitez](https://github.com/timwhitez).

## Before Opening An Issue

1. Run `./verify.sh`.
2. Record `auto-re-cli --version`.
3. Check the supported host matrix in `README.md`.
4. Remove samples, recovered payloads, secrets, private paths, and proprietary
   output from the report.

Use the repository issue forms for reproducible installer, verifier, CLI, or
Skill problems. Use
[private vulnerability reporting](https://github.com/timwhitez/AutoRE-CLI/security/advisories/new)
for exploitable security defects.

## Repository Boundary

This public repository accepts changes to:

- README and security documentation;
- installer, uninstaller, and verifier behavior;
- the `auto-re` Skill and its public helpers;
- public validation workflows.

Rust source, private specifications, malware samples, target-derived artifacts,
benchmark archives, and internal evidence do not belong in this repository.
Engine changes are reviewed in the private source repository by the maintainer.

## Pull Requests

- Keep the change focused.
- Preserve the static-only safety boundary.
- Add or update a public regression when behavior changes.
- Run `./verify.sh` and the relevant installer or Skill checks.
- Do not commit generated analysis results or untrusted samples.
