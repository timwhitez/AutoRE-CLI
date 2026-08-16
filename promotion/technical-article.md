# Why AI Agents Need Bounded Evidence for Binary Analysis

Binary reverse engineering and AI agents appear to fit naturally together. A
disassembler or decompiler produces text, an Agent reads that text, and the
Agent explains the program. The difficult part is not producing more text. It
is preserving the boundary between what the analyzer proved, what it inferred,
what it did not inspect, and what static analysis cannot establish.

AutoRE-CLI was designed around that boundary.

## The Problem With Unbounded Decompiler Dumps

Large analysis dumps create three recurring problems:

1. **Context pressure.** Thousands of functions and instructions consume the
   Agent's context before a useful hypothesis is selected.
2. **Lost provenance.** A conclusion can become detached from the function,
   address, budget, warning, or parser state that produced it.
3. **False completeness.** A successful process exit is easily mistaken for a
   complete whole-program result, even when pagination or recovery limits were
   reached.

The solution is not a larger dump. It is a bounded investigation protocol.

## A Bounded Result Is More Than JSON

AutoRE-CLI's Agent-facing results include:

- an explicit selector and input identity;
- function, instruction, graph, and record budgets;
- warnings and unsupported states;
- complete versus truncated status;
- current findings with evidence strength;
- exact static next actions and stop conditions;
- bundle ownership, byte counts, and SHA-256.

This allows an Agent to answer a smaller question, validate the artifact it is
reading, and follow only one continuation that advances the investigation.

## Four Evidence States

The most important output distinction is:

- **Validated:** directly supported by returned fields and provenance.
- **Inferred:** a bounded heuristic or interpretation with recorded evidence.
- **Unresolved:** ambiguous, unsupported, or outside the inspected window.
- **Not claimed:** plausible behavior that the static evidence does not prove.

For example, a static graph can validate that one function references another.
It cannot by itself prove that the call executes at runtime. A demangled Rust
symbol can provide language and naming evidence. It does not prove ownership,
drop order, or a complete source module. A packer signature is evidence of a
protection mechanism, not proof that unpacking succeeded.

Keeping these states separate is more valuable than making the pseudo output
sound confident.

## Static-Only Is a Product Boundary

AutoRE-CLI never executes:

- the target binary or object;
- recovered shellcode;
- decoded, unpacked, or embedded payloads;
- target-derived scripts or executables.

It does not move a difficult case into a debugger, emulator, sandbox, DBI, JIT,
or runtime trace. Unsupported dynamic behavior remains unresolved.

This is intentionally narrower than a full malware laboratory. It also makes
the control boundary easy for an Agent and operator to reason about.

## A Reproducible Controlled Example

The public repository includes a benign C fixture that is compiled only to an
object file. The object is analysis input and is never executed:

```sh
cc -g -O1 -c examples/controlled/fixture.c \
  -o /tmp/autore-controlled-fixture.o
mkdir -p analysis-results/controlled
auto-re-cli report /tmp/autore-controlled-fixture.o \
  --format json \
  --json-profile ai \
  --sections binary,summary,flow,functions,types \
  --limit 8 \
  --bundle-dir analysis-results/controlled/report.bundle \
  --output analysis-results/controlled/report.bundle/manifest.json
python3 skills/auto-re/scripts/verify_bundle.py \
  analysis-results/controlled/report.bundle/manifest.json
```

In the checked macOS arm64 run, AutoRE-CLI validated a Mach-O AArch64
relocatable object and a one-function inventory. It completed without warnings
or truncation, inferred a static flow root, and explicitly kept absent type
evidence as `not_claimed`.

That last result matters. “No recovered type evidence in this selected
section” is more honest and operationally useful than inventing a structure
from weak clues.

## Safe Next Actions

An Agent-oriented result can emit an exact `argv[]` for a focused function,
CUSTOM IL, CFG, or another bounded surface. The Agent should:

1. validate the parent result or bundle;
2. select one relevant action;
3. review the exact argument vector;
4. execute it without shell interpolation;
5. stop when the recorded stop condition is met.

The included helper rejects a non-AutoRE program, execution flags, inherited
output paths, and parent-result overwrite.

## Where AutoRE-CLI Fits

AutoRE-CLI is not a replacement for every reverse-engineering framework.
Ghidra and Rizin provide mature interactive ecosystems. angr adds symbolic
analysis. capa excels at rule-based capability identification. Ghidra MCP
projects make an existing GUI environment conversational.

AutoRE-CLI's specific role is a prebuilt, offline, CLI-first evidence surface
whose output and continuation protocol are designed for both automation and
Agents.

## Public Distribution Boundary

The public AutoRE-CLI repository contains compiled engine binaries and the
MIT-licensed Agent Skill, helpers, installer, verifier, release automation,
controlled examples, and documentation. The Rust engine implementation is not
published.

This boundary is explicit because distribution trust and open-source licensing
should not be confused with source availability.

## Try It

The GitHub Releases page provides independently verifiable 7–8 MB archives for
macOS arm64/x86-64, Linux arm64/x86-64, and Windows x86-64.

Repository and controlled demo:

https://github.com/timwhitez/AutoRE-CLI
