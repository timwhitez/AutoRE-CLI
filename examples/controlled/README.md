# Controlled Demo Fixture

`fixture.c` is an independently authored, benign input for demonstrating
AutoRE-CLI. The generated object is analysis input only and must not be
executed.

On macOS or Linux:

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

This example intentionally produces an object file rather than a runnable
program. AutoRE-CLI performs static analysis only.
