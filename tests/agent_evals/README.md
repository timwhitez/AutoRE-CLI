# Agent task evaluation contract v1

These are offline maintainer assets, outside the installed Skill. The Skill
validator recognizes `evals/trigger_cases.json` specifically, not an arbitrary
task-eval home. No Skill instruction, version or managed inventory changes.

## Reproduce

The historical reference runner requires **CLI 0.1.10**, not the current 0.1.13
release. Use two separate Git checkouts: the evaluator at
`908bb8fc59517bac9aad12d4ca85d9bb947e45f3`, and the historical public distribution
at `32703cd79c227b1ac88912c8aae00585c1641147`. Run the evaluator from its own
checkout; the historical checkout need not contain the current evaluator.
Python 3.10+ and Linux x86-64 are required for the reference run. Other hosts
can run the unit tests and scorer. No compiler or model API is needed.

Create these checkouts in an existing trusted parent, using fresh directory
names. The following commands use full commits, rather than moving branches or
a tag whose version alone cannot establish helper compatibility:

```sh
set -eu
cd /trusted/reproduction

git clone https://github.com/timwhitez/AutoRE-CLI.git evaluator
git -C evaluator checkout --detach 908bb8fc59517bac9aad12d4ca85d9bb947e45f3
git clone https://github.com/timwhitez/AutoRE-CLI.git public-0.1.10
git -C public-0.1.10 checkout --detach 32703cd79c227b1ac88912c8aae00585c1641147

EVALUATOR=$(cd evaluator && pwd -P)
PUBLIC=$(cd public-0.1.10 && pwd -P)
OUTPUT=/trusted/reproduction/new-reference-run
export EVALUATOR PUBLIC OUTPUT

# Preflight before the runner creates any output or probes the CLI version.
python3 -B - <<'PY'
import hashlib
import os
import platform
from pathlib import Path
import subprocess

def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()

evaluator = Path(os.environ['EVALUATOR']).resolve()
public = Path(os.environ['PUBLIC']).resolve()
output = Path(os.environ['OUTPUT'])
assert evaluator != public, 'use separate evaluator and historical public roots'
for root, expected in (
    (evaluator, '908bb8fc59517bac9aad12d4ca85d9bb947e45f3'),
    (public, '32703cd79c227b1ac88912c8aae00585c1641147'),
):
    assert Path(git(root, 'rev-parse', '--show-toplevel')).resolve() == root, 'not an independent Git root'
    assert git(root, 'rev-parse', 'HEAD') == expected, 'unexpected Git HEAD'
    assert not git(root, 'status', '--porcelain'), 'checkout must be clean'
    print(root.name, expected, git(root, 'rev-parse', 'HEAD^{tree}'))
assert platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux x86-64 required'
assert not output.exists() and not output.is_symlink(), 'output must be new'
assert output.parent.is_dir(), 'output parent must exist'
rows = dict(line.split('  ', 1)[::-1] for line in (public / 'SHA256SUMS').read_text().splitlines())
for relative in (
    'bin/linux-x86_64/auto-re-cli',
    'skills/auto-re/scripts/read_result.py',
    'skills/auto-re/scripts/run_next_action.py',
    'skills/auto-re/scripts/process_control.py',
):
    path = public / relative
    assert path.is_file() and not path.is_symlink(), 'missing or linked input: ' + relative
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert rows.get(relative) == actual, 'checksum mismatch: ' + relative
    # Also bind the bytes to the fixed Git tree, not just an editable checksum row.
    committed = subprocess.check_output(['git', '-C', str(public), 'show', 'HEAD:' + relative])
    assert hashlib.sha256(committed).hexdigest() == actual, 'input differs from fixed Git tree'
    print(relative, actual)
version = subprocess.check_output([str(public / 'bin/linux-x86_64/auto-re-cli'), '--version'], text=True).strip()
assert version == 'auto-re-cli 0.1.10', 'unsupported CLI version: ' + version
print(version)
PY

python3 -B -m unittest discover -s "$EVALUATOR/tests" -p test_agent_task_evals.py -v
python3 -B "$EVALUATOR/tests/agent_evals/reference.py" --public-root "$PUBLIC" --output "$OUTPUT"
python3 -B "$EVALUATOR/tests/agent_evals/scorer.py" "$OUTPUT/records.json" --evidence-root "$OUTPUT/evidence"
```

This fixed pair was exercised on Linux x86-64: all seven reference cases
completed, and the generated hash-bound records were rescored. The historical
CLI SHA-256 was
`bbb997472d1ae7d1abfec29fe1e1bd5c6599ffbcb1a4f5a3937d4f8ce410b0bd`.
A separate fresh run with `--history-root "$PUBLIC"` also completed seven cases
and six helper comparison rows. These are scripted reference results; real
Agent/model runs remain **NOT_RUN**. This does not change `baseline.json`, its
historical scores, or any release identity.

`--history-root` is optional and is used only for immutable helper before/after
comparisons. It does not replace `--public-root` or provide the reference CLI.
Use another fresh output directory when adding it. Reusing an existing output
is rejected; preserve accepted records and choose a new name.

The preflight rejects a current 0.1.13 root, changed binary/checksum bytes,
missing helpers, unsupported host, and a pure archive with no independent Git
metadata. In particular, `git rev-parse HEAD` inside an archive nested in some
other repository can report that parent's HEAD: require the exact top-level
and historical HEAD above. Do not edit VERSION, replace the CLI, bypass the
version check, or silently substitute an archive for Git provenance.

The runner itself checks binary hash and version before `output.mkdir()`, then
creates fixtures **before** querying the public Git HEAD. Therefore a Git
failure may leave a newly created output/evidence directory. The preflight
avoids that known failure path; it is not a zero-write guarantee under later
mutation or failure. Existing output is never overwritten. An archive-only
provenance mode would require a separate explicit design and is not supported.

The runner executes only the checksum-verified trusted CLI and checked-in
Python helpers. It never executes the inert fixture bytes. Synthetic artifacts
test retrieval and consumer behavior, not engine semantics or model quality.

`cases.json` has exact `kind=auto_re_agent_task_cases`, integer
`schema_version=1`, fixture source/compile settings, seven task prompts,
cold/retained phases, reference plans, independently defined facts and required
boundaries. Expected facts come from input bytes/base, the documented CLI
contract, or the synthetic JSON constructor, never analyzer output. Large text
uses a `value_encoding=repeat` recipe. Synthetic artifacts test retrieval and
consumer behavior; they cannot certify engine recovery or program semantics.
Known direct calls remain valid; help is used only for unfamiliar parameters.
CFG span/terminal-edge facts and the known final `ret` derive from the four raw
fixture bytes; an address alone cannot complete the CFG task. Reference plans
are examples; verified-original host reads can produce the prescribed evidence
files without using the optional reader.

## Claim rubric

A result supplies atomic claims, not prose keywords. Each claim contains `fact`,
exact typed `value`, boolean `polarity` and `evidence[]`. Positive polarity
asserts equality; negative polarity denies equality. To earn credit it must
assert the independently expected value positively and cite at least one allowed
artifact/pointer whose actual value agrees. Thus a negated answer, a true fact
with irrelevant evidence, and a correct keyword without a supporting value all
fail. A negative expected boolean is represented as `value=false, polarity=true`.
Unlisted factual claims are unsupported, even if plausible. Duplicate claims,
wrong values/types, hash mismatch, missing files and wrong pointers fail. Hashes
provide integrity, not authority: review the transcript and artifact provenance
before accepting real-Agent evidence. Free-form answers must be manually split
into *all* atomic claims first; this scorer does not parse natural language or
certify unrecorded prose. No inferred text is scored as validated semantics.

Every required boundary ID must be explicitly acknowledged. IDs mean exactly:
`static_only`: no runtime observation; `selected_scope`: selected body, not
whole-program coverage; `help_is_not_analysis`: parameter discovery only;
`synthetic_not_semantics`: fixture values, not recovered semantics;
`partial_analysis`: truncation/partial coverage preserved;
`complete_inventory_absent`: absence only within the complete fixture inventory;
`partial_inventory_unknown`: empty partial evidence cannot prove absence;
`no_reanalysis`: retained tasks require zero analysis calls;
`corrupt_not_evidence`: corrupted content is unusable and processing must stop.
The reference runner checks source warnings/completion where applicable.
Boundary IDs are explicit structured acknowledgements, not keyword detection;
human review must verify their meaning in a real answer.

Per-claim credit is binary. Correctness = supported correct claims / required
facts (0 when none); completion requires every fact, every boundary, no incorrect
or unsupported extra claim, and task-specific call constraints. Costs never
compensate for incorrectness. A corrupted read is an expected safe failure, not
an invalid call. An invalid call is a rejected/malformed request, independently
of expected nonzero tool outcomes. Compare cold and retained tasks separately.

## Result record v1

`kind=auto_re_agent_task_results`, integer `schema_version=1`, `runs[]`.
Each run has `case_id`, matching `phase`, `completed` (self-report), `claims[]`,
`boundaries[]`, `calls[]`, `provenance`, `usage`, and `resources`.
Evidence references have `artifact` (relative to evidence root), `sha256`, and
RFC 6901 `pointer`. Supporting artifacts are exact per-case allowlisted names;
paths must stay under the evidence root. Artifacts are strict JSON, capped at
4 MiB; controls at 1 MiB. Unknown kind/version and malformed records fail closed
with `invalid_eval_record`; missing/unusable claim evidence earns zero credit.

Each call records argv, role (`analysis`, `retrieval`, `help`, `admission`),
validity, exit code, stdout/stderr bytes, latency milliseconds and `request_id`
for analysis. Request IDs bind the same input/selector/budget; the scorer derives
repeated analysis from duplicate IDs rather than trusting a claimed total.
Costs expose total calls, invalid calls, repeated analysis, retrieval calls,
response bytes and summed tool latency. `usage` records `unit` (`utf8_bytes` or
`tokens`), input/output counters and method; the baseline declares UTF-8 response
bytes as its output proxy, not model tokens, and zero model input. `resources`
records peak RSS/CPU or null plus a reason. Baseline resource sampling is
NOT_MEASURED; response size is measured. Wall latency varies with host load.

`provenance` records mode (`reference` or `agent`), model and version (null for
reference), prompt, tools, inputs/hashes, repetition count, transcript reference
and candidate revision. Agent mode requires nonempty model/version/transcript;
actual runs require separate explicit authorization. Real-Agent results are
**NOT_RUN**. No model win rates, installed release compatibility or engine
correctness are inferred from reference plans.

## Baseline and candidate comparisons

`baseline.json` archives bounded cost/score records, fixture/input and CLI
identities, observed capability outcomes and immutable public candidate commits.
Full generated analysis artifacts remain disposable; rerun to regenerate them.
These are reference plans, not Agent runs. Scoring the newly generated
`records.json` reopens hash-bound artifacts, including exact string reconstruction.

The optional `--history-root` argument points at a public Git checkout containing
merged PRs #44/#45/#46 (issues #40/#41/#42). Only those immutable helper trees are
exported into temporary directories. The runner compares each merge's first
parent with that merge, using the same fixtures and plans:

- #40: duplicate analysis identity for newly covered `dump-cfg`; report whether
  continuation blocks an identical successful prior request.
- #41: original large value attempts versus string/keys recovery; require exact
  text reconstruction and complete document-order keys, preserving boundaries.
- #42: admission of a spec-derived function-kind DTO, plus wrong-kind and unknown
  version rejection. This is consumer compatibility, not a shipped P1 producer.

Costs include helper subprocesses, not setup/version/hash checks. #40/#42 use a
small trusted adapter to invoke the actual revision's library APIs; its JSON
output is measured and is not a process receipt or admission authorization.
Candidate deltas demonstrate tool capability only. Safe unknown-version
rejection already worked before #42; it must not be claimed as an improvement.
A failed before plan is retained, not silently retried with larger budgets.

Archived reference observations (one repetition, Linux x86-64, CLI 0.1.10):

| Case | Phase | Calls | Response bytes | Supported completion |
| --- | --- | ---: | ---: | --- |
| Direct CFG | cold | 1 | 318 | yes |
| Unfamiliar IL help | cold | 1 | 3,267 | yes |
| Known function | cold | 1 | 5,315 | yes |
| Large string + keys | retained | 9 | 67,578 | yes |
| Absent vs unknown | retained | 2 | 1,453 | yes |
| Existing result | retained | 1 | 630 | yes |
| Corrupted artifact | retained | 1 | 134 | yes (safe stop) |

All seven plans have zero invalid calls and zero repeated analysis. These
numbers include reader envelopes and depend on output paths; they are not
model-token or lower-latency claims. #41 increases recovery cost from two safe
failures (248 bytes, no answer) to nine successful calls (67,578 bytes, exact
answer). #40 adds previously unavailable duplicate blocking; #42 adds reserved
function-kind admission while both negative controls continue to reject. No
negative-control improvement or resource-use reduction is claimed.
