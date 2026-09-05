# Local continuation safety tests

From the distribution root, run:

```sh
python -B -m unittest discover -s tests -p 'test_run_next_action*.py' -v
```

The standard-library-only suite executes controlled Python child processes and
never executes analyzed samples, shellcode, or recovered artifacts. `-B` keeps
bytecode out of the checksum-managed distribution. No network access, API keys,
GitHub Actions, or installed Auto-RE binary are needed for these tests.

The suite covers exclusive receipt creation, late collisions, failure cleanup,
POSIX creation permissions, manifest-kind validation, resolved sink separation,
dry-run/execution preflight parity, and bounded diagnostic tails. The source
repository discovers this same suite through its distribution test shim.

## Contract and limits

Receipt destinations must be new. A failed exclusive create must leave the
existing file or symlink intact. Failure cleanup checks the identity of a file
created by that operation and does not knowingly remove a replacement. On
POSIX, files are created with requested mode 0600 (the umask may restrict it)
and finish read-only; this is not a Windows ACL guarantee.

Dry-run and execution share receipt preflight. Existing symlinks and dot
segments are resolved before rejecting overlapping analysis/diagnostic paths
in either direction. Literal `~` in an emitted argv is not shell-expanded.
Tail retention accepts integers from zero through 1 MiB per stream; full-stream
hashes and byte counts are retained even when the tail size is zero.

Use a stable, trusted receipt parent and trusted CLI. These checks are not an
atomic filesystem sandbox against an adversary changing parent directories or
pathnames between operations. A successful dry-run neither reserves paths nor
guarantees that execution will still pass after the filesystem changes.

Linux Python results are not evidence of native Windows/macOS behavior, Rust
engine correctness, full distribution verification, or target analysis quality.
The existing binary version and build provenance remain unchanged by a
Python-only repository hotfix; published release archives are separate assets.
