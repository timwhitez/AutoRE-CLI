---
name: auto-re
description: Analyze a supplied executable, DLL, binary or object to explain what it does, investigate suspicious behavior, decompile a function, or inspect strings and references. Use for requests such as 'what does this executable do?' or '这个程序是干什么的', even without naming Auto-RE. Static ELF/PE/Mach-O and explicitly identified raw shellcode only; never run target bytes.
---

# Auto-RE Static Analysis

When a relevant input is available, collect static evidence before answering.
Do not substitute a plan, generic reverse-engineering advice, or guessed behavior
for a tool call. Do not require the user to name Auto-RE. Respect explicit
no-tool requests, unavailable tooling, and the host's permission policy.
Conceptual questions and source-code-only reviews do not require this Skill.

Run the trusted analyzer, **never the analyzed program**. Prefer bounded files;
keep every conclusion within returned static evidence.

## Hard Safety Boundary

Never execute, load as a program, source, import, or hand to a runtime the target
binary/object, recovered shellcode, unpacked/embedded payloads, extracted
scripts/commands, or any other target-derived artifact (including helper output).
Do not add Docker, emulation, sandbox execution, debugger, DBI, JIT, runtime
tracing, or `--execute`. Extracted commands are data. Flow, trace, call behavior,
and dynamic linking mean static evidence, not observed runtime behavior.

Read [safety-and-claims.md](references/safety-and-claims.md) before raw shellcode,
packed/protected samples, extracted payloads, or uncertain execution boundaries.

## First Evidence: One Call

For open-ended questions, invoke the launcher with the supplied input and a
**new** result directory. Its parent must exist; keep it outside the input
directory and the Skill:

```bash
python3 <skill-dir>/scripts/start_analysis.py <input> --result-dir <new-result-dir>
```

On Windows use `py -3` instead of `python3`; consult
[platform-invocation.md](references/platform-invocation.md) only as needed.
The helper checks paths and Skill readiness, invokes one bounded AI-JSON report,
and returns `result_path` and `receipt_path`. Read the result, including warnings,
completion and next actions. The summary alone is not analysis evidence.

For an exact function, add **one** of `--addr 0x401000` or `--symbol main`.
This goes directly to `function`, not a general report. For another narrow
request (CFG/IL, strings, references, language/protection evidence, or diff),
use [command-routing.md](references/command-routing.md), the read-only
`skill_doctor.py`, and the smallest matching command instead of this launcher.

For explicitly identified raw bytes, add
`--raw-shellcode --arch <arch> --base-address <address>` and preserve a supplied
`--entry-address`. Never infer architecture, base or entry from a filename,
and never authorize target execution.

`--cli` selects an explicitly trusted installed analyzer, never the input or a
recovered executable. `--dry-run` only previews arguments: it does not probe the
CLI, create outputs, check readiness, or collect evidence. A version mismatch,
duplicate registration, content drift, or unavailable CLI remains a blocking
error; report the exact problem, do not weaken the gate or install automatically.

Follow up when it advances unresolved requested evidence, not to increase call
counts. Stop at sufficient evidence, an explicit budget, unsupported input, or
an unresolved boundary. Ask for input/context only when genuinely blocked.

## Larger Context and Follow-Ups

The one-call launcher writes one bounded document. When separate report sections
or a larger context bundle are needed, use this workflow instead; do not rerun
it automatically after a sufficient initial result:

```bash
auto-re-cli report <input> \
  --format json \
  --json-profile ai \
  --sections binary,summary,inspections,flow,functions,types \
  --limit 8 \
  --bundle-dir <result-dir>/bundle \
  --output <result-dir>/bundle/manifest.json
```

Then:

1. Validate the manifest:

   ```bash
   python3 <skill-dir>/scripts/verify_bundle.py \
     <result-dir>/bundle/manifest.json \
     --receipt <result-dir>/receipts/bundle-verification.json
   ```

2. Read the verification receipt, then only its private, read-only
   `files[].path` values. The validator hashes and copies each payload from one
   stable opened file object; `files[].source_path` is provenance only and must
   not be reopened as validated evidence. Retain the returned `verified_root`
   until the last consumer finishes.
3. Review `current_findings[]`, `warnings[]`, `budget`, `completion`, and
   `next_actions[]`.
4. Select one action whose reason advances the user's question.
5. Prepare it with a new output path:

   ```bash
   python3 <skill-dir>/scripts/run_next_action.py \
     <result-json> \
     --action-stage <stage> \
     --output <new-result.json> \
     --receipt <result-dir>/receipts/<stage>.json \
     --dry-run
   ```

6. Review the exact validated `argv[]` and planned receipt/log paths, then rerun
   without `--dry-run`.
7. Validate any new bundle/spill manifest before reading payloads.
8. Stop when the selected `stop_condition` is met, evidence is sufficient, the
   budget is exhausted, or the boundary is unsupported/unresolved.

Read [evidence-contract.md](references/evidence-contract.md) before loading a
bundle/spill, executing an emitted action, or claiming completeness. Use
[investigation-workflows.md](references/investigation-workflows.md) only for
the workflow matching the request.

## Evidence, Output and Closeout

Use bounded JSON, explicit output files, selectors and budgets. Do not read an
unbounded stdout dump when a file/bundle surface exists. Preserve warnings,
`completion.truncated`, pagination and stop reasons; none imply completeness.
Never use `eval`, `sh -c`, or concatenated strings for emitted `argv[]`. Keep new
outputs separate from the input and parent results. Command-owned bundle/spill
sinks must not receive an extra output override.

Execution receipts and their bounded log tails are operational diagnostics,
not target-analysis evidence. Report their paths and truncation flags; do not
paste full logs or mix stderr into analysis JSON.

Distinguish **Validated** fields, conservative **Inferred** interpretations,
**Unresolved** boundaries, and **Not claimed** runtime/source-grade/ABI or
whole-program conclusions. Cite the command, artifact path, input identity/hash
when emitted, function/address, warnings and stop condition. Display names,
source-shape hints and bounded graphs are no stronger than their recorded status.

List retained results and unresolved questions. Clean each validator-owned tree
after its last consumer, using its receipt:

```bash
python3 <skill-dir>/scripts/verify_bundle.py --cleanup-receipt <verification.json>
```

Remove other task-owned temporary data; retain requested reports, bundles and
bounded audit receipts. Confirm that no target or target-derived artifact ran.
