# AutoRE-CLI Launch Kit

This file contains ready-to-publish copy. Confirm that the GitHub Release and
its platform assets are live before posting.

## Core Positioning

AutoRE-CLI is a public binary distribution for bounded, evidence-backed static
reverse engineering by analysts and AI agents. It provides traceable JSON,
CFG/IL, readable pseudo output, Go/Rust and PE evidence, verified bundles, and
safe next actions without executing target bytes.

## Show HN

**Title**

```text
Show HN: AutoRE-CLI – Bounded static binary analysis for AI agents
```

**First comment**

```text
I built AutoRE-CLI because giving an AI agent an unbounded decompiler dump tends
to produce context overflow and overconfident conclusions.

The tool analyzes ELF, PE/COFF, Mach-O, object files, and explicitly identified
raw shellcode without executing target bytes. Its JSON output includes budgets,
warnings, completion/truncation state, evidence strength, verified bundle
manifests, and exact bounded next actions.

The public repository is intentionally a binary distribution: the Agent Skill,
installer, verifier, release automation, controlled demo, and docs are
MIT-licensed, while the Rust engine implementation is not published.

There are approximately 7–8 MB packages for macOS arm64/x86-64, Linux
arm64/x86-64, and Windows x86-64. I would especially value feedback on the
evidence contract, static-only safety boundary, and integration ergonomics.

Repository: https://github.com/timwhitez/AutoRE-CLI
```

## Reddit r/ReverseEngineering

**Title**

```text
[Tool] AutoRE-CLI: bounded static reverse engineering output for analysts and AI agents
```

**Body**

```text
Author here. I am releasing AutoRE-CLI, a CLI-first binary distribution focused
on bounded, machine-readable static evidence rather than conversational control
of a GUI.

It supports ELF, PE/COFF, Mach-O, objects, and explicitly identified raw
shellcode. Analysis surfaces include functions, CFG, multiple IL levels,
pseudo output, calls/data references, PE inventories, Go/Rust evidence,
archive/replay, and semantic diff.

The part I would most like technical feedback on is the evidence model:
validated, inferred, unresolved, and not-claimed findings are kept separate,
and every agent-oriented result carries budgets, warnings, completion state,
and bounded next actions.

The tool never executes target bytes or target-derived artifacts. The public
repo contains binaries plus the MIT-licensed Skill, installer/verifier,
release automation, controlled demo, and docs; the Rust engine source is not
published.

Demo and downloads:
https://github.com/timwhitez/AutoRE-CLI
```

## X / Mastodon

```text
Released AutoRE-CLI: bounded, evidence-backed static reverse engineering for
analysts and AI agents.

ELF · PE/COFF · Mach-O · CFG/IL · Go/Rust · archive/replay/diff

No target execution. Explicit budgets, warnings, evidence states, verified
bundles, and safe next actions.

https://github.com/timwhitez/AutoRE-CLI
```

## LinkedIn

```text
I have released AutoRE-CLI, a public binary distribution for bounded static
reverse engineering by human analysts and AI agents.

The design focuses on a problem that appears when binary-analysis output is fed
to an Agent: large dumps lose provenance, consume context, and encourage claims
that exceed the inspected evidence. AutoRE-CLI instead emits bounded JSON with
explicit budgets, warnings, completion state, evidence strength, and exact
follow-up actions.

It supports ELF, PE/COFF, Mach-O, object files, and explicitly identified raw
shellcode, while preserving a strict static-only boundary.

The repository includes a reproducible benign demo and 7–8 MB packages for five
host targets:
https://github.com/timwhitez/AutoRE-CLI
```

## Chinese Short Post

```text
发布 AutoRE-CLI：面向人类分析师与 AI Agent 的有界纯静态逆向工程工具。

它支持 ELF、PE/COFF、Mach-O、object file 和明确标识的 raw shellcode，输出
带预算、warning、completion state、证据强度和安全下一步动作的可追溯 JSON。

与把大段反编译结果直接塞给 Agent 不同，AutoRE-CLI 会明确区分 validated、
inferred、unresolved 和 not_claimed，并且绝不执行目标或目标派生产物。

仓库提供可复现无害 Demo，以及 macOS、Linux、Windows 五个平台的 7–8 MB
独立发行包：
https://github.com/timwhitez/AutoRE-CLI
```

## Directory Description

```text
AutoRE-CLI — a static-only binary analysis CLI and Agent Skill that emits
bounded, evidence-graded JSON, CFG/IL, pseudo output, verified bundles, and
safe next actions for ELF, PE/COFF, Mach-O, objects, Go/Rust evidence, and
repeatable diff workflows.
```

## Launch Checklist

- GitHub tag and Release exist.
- All five platform assets and `SHA256SUMS.release` are attached.
- Release downloads and internal `verify` commands pass.
- Social preview PNG is uploaded in repository settings.
- README Release badge resolves.
- Homebrew and Scoop package repositories are live before advertising them.
- Maintainer is available to respond to technical questions after posting.
