# Offline regression tests

Run from the repository root with Python 3.10 or newer; no third-party packages
or GitHub Actions are needed:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The suite uses temporary files, inert binary-shaped bytes, and controlled
Python subprocesses only. It never executes analyzed samples. Archive tests
exercise real ZIP/tar and checksum code with the canonical static distribution
verifier against synthetic members; they do not certify production binaries.
POSIX permission/replacement checks are skipped where unsupported; Windows ACLs
and reparse behavior require native Windows testing. This is not the Rust
workspace test suite.

Receipts share producer, admission and prior-reader limits: 256 KiB including
the final newline, depth 16, 10000 values, 1000 entries per container and 65536
decoded UTF-8 bytes per string/key. Known metadata is rejected before version
probing; actual program/version/identity admission precedes analysis and logs.
The dry-run `receipt_budget` reports the derived encoded upper bound while
`program_and_identity_checked` remains false. No evidence is truncated to fit.
The budget reserves bounded version output, process diagnostic prefixes plus
256 exception characters in each of eight entries, fixed timestamp/status/hash
formats and explicit 64-bit counter/duration/exit ranges. The final writer
checks the same size, shape and identity contract; round-trip regressions use
the real prior loader rather than plain JSON decoding.

Release builds now require a **new output directory in an existing trusted
parent**. Existing directories (including empty ones) are rejected rather than
cleared. The default remains `release-assets`; choose a fresh name for another
build, for example `--output /trusted/builds/release-assets-run-2` with an
existing `/trusted/builds` parent outside the checkout. Within the checkout, use a new child of an existing `release-assets` directory. All
archives and checksums are staged before the completed directory is published.
Trusted parents are required; these checks do not provide a sandbox against
hostile concurrent directory mutation.

Reader recovery tests preserve all v1 cases and exercise v2 `keys`/`string`
pages: document-order keys and escaped pointer round-trips, exact Unicode
scalar reconstruction, hash-bound continuation, explicit typed failures, and
the complete 16 KiB envelope including newline. The blocked-task cases use
synthetic data matching controlled static-analysis artifact shapes; generated
analysis results and target binaries are not packaged. Direct host reads of a
verified original artifact remain valid. Views cannot be action-runner roots.

Request identity tests pin the CLI 0.1.10 command contract and option arities in
`fixtures/cli_identity_0_1_10.json`. The table covers all subcommands, including
explicit exclusions; unknown versions yield `unsupported_command`. This tests
identity coverage, independently of execution admission. Source tests compare
the fixture with the actual Clap model; public tests need no Rust toolchain.

Result admission fixtures in `fixtures/result_contract_0_1_10.json` contain real
static CLI 0.1.10 DTOs from inert controlled inputs, with binary/input/stdout
digests and exact argv. Selected kinds add only `kind` and are producer-verified by source #344
against the frozen DTOs. The public 0.1.10 binary lacks the selector; these
fixtures do not certify a release or installed pair. The suite checks P0/C1 and producer-verified
P1/C1, mutations, passive additive evidence and command-bound first evidence.
C0/P1 selected forms are unsupported and fail closed. Installed release pairs
remain NOT_VERIFIED; checkout tests do not certify an upgrade.

Task outcomes are evaluated by the maintainer-only
[`agent_evals/README.md`](agent_evals/README.md) contract. Seven independent
fixture cases, an atomic-claim/evidence scorer, safe-stop and negation failures,
and scripted cold/retained baselines extend routing tests. The bounded baseline
compares merged #40/#41/#42 with each first parent; response bytes are an explicit
token proxy. No model calls or Skill instruction/version changes are included.
