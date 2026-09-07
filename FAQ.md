# Frequently Asked Questions

## Is AutoRE-CLI open source?

This repository is an MIT-licensed public binary distribution. The Agent
Skill, deterministic helpers, installer, verifier, release automation,
controlled examples, and documentation are open source here. The Rust engine
implementation is not published.

## Does AutoRE-CLI execute the analyzed file?

No. The product boundary is static-only. It does not execute targets,
shellcode, recovered payloads, embedded objects, or target-derived artifacts.
It does not use a debugger, emulator, sandbox, DBI, JIT, or runtime tracing.

## What does “evidence-backed” mean?

Output separates direct validated facts from bounded inferences, unresolved
questions, and facts the tool does not claim. Machine-readable results also
include warnings, budgets, completion state, truncation, provenance, and stop
conditions.

## Why not just use Ghidra, Rizin, angr, or capa?

Those tools solve adjacent problems and can be the better choice. AutoRE-CLI
focuses on a prebuilt, CLI-first, bounded JSON contract that human analysts and
AI agents can consume without a GUI or analysis service. See the comparison in
the main README.

## Does it recover the original source code?

No. Pseudo output, demangled names, source-shaped hints, recovered types, and
language evidence are bounded static evidence. They are not proof of complete
or source-identical recovery.

## Which inputs are supported?

The public release supports ELF, PE/COFF, Mach-O, universal Mach-O, object
files, and explicitly identified raw shellcode for supported architectures.
Run `auto-re-cli <command> --help` for the exact command options.

## Why must raw shellcode include architecture and base address?

Those are caller-provided facts that cannot be safely inferred from a
filename. AutoRE-CLI requires them explicitly and preserves them in follow-up
actions.

## Can I analyze malware?

Yes, statically. Keep samples read-only, store output separately, never execute
extracted content, and do not upload samples or sensitive output to public
issues. Read `SECURITY.md` first.

## Does installation access the network?

No. Downloading or cloning is separate from installation. The installer
verifies the extracted distribution and then copies only the selected binary
and Skill files.

## Why are the macOS and Windows binaries not fully signed?

macOS artifacts are ad-hoc signed and not notarized. The Windows artifact is
not Authenticode signed. The release manifest and SHA-256 verifier provide
integrity and provenance within the authenticated release channel, but they do
not replace platform code signing.

## How should an Agent use the emitted next actions?

Validate the result or bundle first, select one relevant action, review its
exact `argv[]`, and execute it as an argument vector rather than through
`eval`, `sh -c`, or string concatenation. The included helper enforces these
constraints.

## Where should I report a problem?

Use GitHub Issues for reproducible CLI, installer, verifier, Skill, or
documentation problems. Use private vulnerability reporting for exploitable
security defects. Never attach malware, recovered payloads, secrets, private
paths, or proprietary analysis output.

## Why are there only a few functions in a large Go binary?

Language detection, recovered names, discovered functions, analyzed bodies and
emitted rows are different counts. A finished page or `warnings: []` does not
prove discovery is complete. Check `inspect-go` metadata, the selected window,
noise filtering and discovery budgets. A present Go section with no parsed
`pclntab` names is unresolved metadata, not proof that no Go functions exist.
Changing `--limit` only changes an output window; it cannot repair discovery.

## Why does a call graph stop at an indirect call?

Read `unresolved_edge_count`, truncation and stop reasons, not only warnings.
Inspect the callsite with `function`, `dump-il`, `data-xrefs` or `aarch64-refs`.
An address reference may provide a candidate, but is not by itself a validated
call edge. Zero known callers does not mean unreachable. Widen depth only when
it addresses the missing evidence; a larger graph can remain incomplete.

## How do I handle repeated actions or large output?

Compare the input identity, command, selector, page and budgets. Stop an
identical action that yields no new evidence. Prefer a selected function slice,
progressing page or supported spill/bundle over dumping every IL layer. Keep
stderr and operation receipts separate from analysis JSON. Record unresolved
questions rather than treating retry exhaustion as a successful investigation.

## Are readable decoded strings confirmed behavior?

No. Printable text and keyword scores rank candidates; they do not prove a
transform, call linkage, endpoint use or malicious intent. Preserve raw bytes,
encoding, length, source addresses, transform evidence and conflicting results.
Use strict UTF-8 validation where relevant; do not silently replace invalid
bytes. Do not run sample-specific simulators or recovered scripts to fill gaps.

## Why does Skill diagnosis report a duplicate or old version?

Record the resolved CLI path/version and all discovered Skill roots. A checkout,
installed copy and legacy registration can differ. Follow the managed install
workflow after selecting the intended version; do not disable the check or
silently delete another registration. Release documentation describes that
release, not necessarily the analyzer currently selected by PATH.
