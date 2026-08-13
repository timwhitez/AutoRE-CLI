# Static Safety And Claim Boundaries

Load this reference for malware, raw shellcode, packed/protected inputs,
embedded payloads, helper configuration, or any request that could be confused
with dynamic analysis.

## Absolute Prohibitions

Do not:

- execute, load, invoke, source, import, or open a target as a program;
- execute recovered shellcode or decoded/unpacked/normalized bytes;
- run generated ELF, PE, Mach-O, object, script, or payload artifacts;
- hand target bytes to an emulator, VM, sandbox, debugger, DBI, JIT, or runtime
  tracing system;
- run extracted installer scripts, commands, macros, or embedded tools;
- mark target-derived files executable;
- use target output as trusted code or as implementation source.

Static parsing with Auto-RE is allowed. Building controlled, independently
authored fixtures for tool validation is allowed, but emitted fixture binaries
must also remain unexecuted.

## Raw Shellcode

Require explicit user or reliable file-context confirmation that the input is
raw bytes. Require architecture and base address; do not guess either. Preserve
the caller's entry address when provided.

An embedded object recovered from a raw blob remains data for static analysis.
Never execute it or write it as an executable follow-up.

## Protection Evidence

`inspect-upx` and `inspect-vmp` are static evidence surfaces.

- Treat `implemented`, `no_go`, `skipped`, `failed`, `partial`, `ambiguous`,
  `unsupported`, and `truncated` as distinct states.
- Follow only emitted bounded playbook actions.
- Return unresolved addresses or stages to the user instead of widening into a
  runtime route.
- Detection is not unpacking; dispatcher candidates are not devirtualization;
  recovered trace/frontier records are not observed execution.

An opt-in UPX helper, when explicitly configured by the operator, is a trusted
static transformer. Its output remains helper evidence and must never execute.
Do not enable or invent a helper command without explicit authorization.

## Containers And Embedded Content

Static inventories of archives, macOS packages, PE resources, scripts, or
embedded objects describe bytes and metadata. They do not establish:

- installation behavior;
- script execution;
- process creation;
- network behavior;
- runtime-loaded modules;
- successful payload handoff.

Do not execute or automatically extract-and-run any listed member.

## Language And ABI Claims

Go and Rust support is evidence-backed but incomplete. Preserve:

- raw symbol identity;
- compiler/version authority boundaries;
- positive and negative ABI proof states;
- unresolved arguments, locals, receivers, captures, return expressions, and
  runtime behavior.

Language hints, demangling, source paths, function inventories, and
source-shaped comments do not prove source-grade reconstruction.

## Safe Closeout

Before finishing:

1. confirm no target or target-derived artifact was executed;
2. list output paths created by Auto-RE;
3. remove task-owned temporary directories that are no longer needed;
4. retain only user-requested reports/bundles;
5. state any warning, truncation, unsupported status, or unresolved claim.
