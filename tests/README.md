# Offline regression tests

Run from the repository root with Python 3.10 or newer; no third-party packages
or GitHub Actions are needed:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The suite uses temporary files, inert binary-shaped bytes, a controlled verifier
fixture, and controlled Python subprocesses only. It never executes analyzed
samples. Archive tests exercise real ZIP/tar and checksum code, but the fixture
verifier does not certify the production binaries or the full distribution.
POSIX permission/replacement checks are skipped where unsupported; Windows ACLs
and reparse behavior require native Windows testing. This is not the Rust
workspace test suite.

Release builds now require a **new output directory in an existing trusted
parent**. Existing directories (including empty ones) are rejected rather than
cleared. The default remains `release-assets`; choose a fresh name for another
build, for example `--output /trusted/builds/release-assets-run-2` with an
existing `/trusted/builds` parent outside the checkout. Within the checkout, use a new child of an existing `release-assets` directory. All
archives and checksums are staged before the completed directory is published.
Trusted parents are required; these checks do not provide a sandbox against
hostile concurrent directory mutation.
