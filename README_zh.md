# AutoRE-CLI

[English](README.md) | [简体中文](README_zh.md)

[![Validate Distribution](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml/badge.svg)](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

AutoRE-CLI 是 Auto-RE 的纯二进制发行仓库。Auto-RE 是面向人类分析师与
AI Agent 的 CLI-first 静态逆向工程引擎。

**由 [@timwhitez](https://github.com/timwhitez) 独立维护和发布。**

本仓库只包含编译后二进制、`auto-re` Skill、离线安装器、SHA-256、发行来源、
第三方许可和用户文档；不公开 Rust 源码仓、私有规格、样本或分析输出。

[安装](#安装) · [Agent 快速开始](#agent-快速开始) ·
[CLI 快速开始](#cli-快速开始) · [支持平台](#支持平台) ·
[完整性](#完整性与来源) · [安全说明](SECURITY.md)

## 核心特点

- **纯静态安全边界**：不得执行目标字节、恢复 shellcode、解包 payload、
  embedded object 或任何目标派生产物。
- **Agent 原生输出**：有界 JSON、显式预算、warnings、stop reason、
  bundle/spill manifest 和可执行 `next_actions[].argv`。
- **分层分析**：反汇编、CFG、LLIL、MLIL、HLIL、CUSTOM IL、可读 pseudo、
  types、calls 与 data references。
- **语言感知证据**：提供有边界的 Go/Rust inventory 与 proof state，不虚构
  source-grade 语义。
- **恶意样本静态检查**：PE resources/strings、static flow、packer/protection
  evidence、batch archive、replay 和 semantic diff。
- **可追溯发行**：每个二进制都绑定源码 revision、尺寸、target、签名状态和
  SHA-256。

## 安装

要求：

- 受支持的 macOS、Linux 或 Windows；
- Python 3.9 或更高版本；
- 不需要 Rust toolchain，也不需要源码 checkout。

```sh
git clone https://github.com/timwhitez/AutoRE-CLI.git
cd AutoRE-CLI
./verify.sh
./install.sh
```

Windows PowerShell 请使用 Python 入口（`py -3` launcher 或 `python` 均可）：

```powershell
git clone https://github.com/timwhitez/AutoRE-CLI.git
Set-Location AutoRE-CLI
py -3 scripts/autore_distribution.py verify
py -3 scripts/autore_distribution.py install
```

默认安装位置：

- CLI：`${AUTORE_INSTALL_DIR:-$HOME/.local/bin}/auto-re-cli`（Windows 为
  `auto-re-cli.exe`）
- Trae Skill：`${TRAE_HOME:-$HOME/.trae}/skills/auto-re`
- Agent Skill：`$HOME/.agents/skills/auto-re`

安装器不访问网络。它先验证完整发行内容，再探测选中的 binary；默认复制而非
symlink，使用 managed marker，并拒绝覆盖 unmanaged destination，除非显式使用
`--replace-unmanaged`。

常用选项：

```sh
./install.sh --dry-run
./install.sh --cli-only
./install.sh --skill-only --agents trae
./install.sh --skill-only --agents codex
./install.sh --skill-only --agents both
./install.sh --install-dir "$HOME/bin"
./install.sh --skill-only --agents codex --codex-home "$HOME/.codex"
```

`--codex-home` 选择旧版 `<home>/skills` 兼容路径；当前默认路径是
`$HOME/.agents/skills`。

确保 binary 目录位于 `PATH`，然后运行：

```sh
auto-re-cli --version
```

### 更新与卸载

拉取或解压新发行后，重新运行 `./verify.sh` 和 `./install.sh`。managed drift、
同版本 repack、降级和额外 Skill 文件都会 fail closed。

```sh
./uninstall.sh
./uninstall.sh --force-managed
```

`--force-managed` 只作用于 marker 列出的已修改文件，不会授权删除无关父目录或
额外用户文件。

## Agent 快速开始

安装后重启或刷新 Agent，然后调用：

```text
使用 $auto-re 对 ./sample.exe 进行纯静态分析，把有界、可追溯的结论写入
./analysis-results。不得执行样本或任何目标派生产物。
```

Skill 会：

1. 验证 `auto-re-cli`；
2. 从有界 AI JSON context bundle 开始；
3. 读取 bundle payload 前验证 ownership、size 和 SHA-256；
4. 分开报告 validated、inferred、unresolved 与 not-claimed；
5. 每次只跟随一个相关的静态 continuation；
6. 在 stop condition、证据充分、预算耗尽或 unsupported 边界处停止。

可用 helper 安全准备一个 emitted action，且不经过 shell interpolation：

```sh
python3 skills/auto-re/scripts/run_next_action.py \
  ./analysis-results/sample.bundle/manifest.json \
  --action-stage function.selected \
  --output ./analysis-results/function-selected.json \
  --dry-run
```

检查 argument vector 后再移除 `--dry-run`。已经拥有 bundle/spill sink 的 action
会拒绝额外 `--output`。

## CLI 快速开始

### 有界 Context Bundle

```sh
mkdir -p ./analysis-results
auto-re-cli report ./sample.exe \
  --format json \
  --json-profile ai \
  --sections binary,summary,inspections,flow,functions,types \
  --limit 8 \
  --bundle-dir ./analysis-results/sample.bundle \
  --output ./analysis-results/sample.bundle/manifest.json

python3 skills/auto-re/scripts/verify_bundle.py \
  ./analysis-results/sample.bundle/manifest.json
```

### 聚焦函数

```sh
auto-re-cli function ./sample.exe \
  --addr 0x401000 \
  --format json \
  --output ./analysis-results/function-401000.json

auto-re-cli dump-il ./sample.exe \
  --level custom \
  --addr 0x401000 \
  --format json \
  --output ./analysis-results/custom-il-401000.json
```

### 显式 Raw Shellcode

```sh
auto-re-cli report ./stage.bin \
  --raw-shellcode \
  --arch x86 \
  --base-address 0x1000 \
  --entry-address 0x1000 \
  --format json \
  --json-profile ai \
  --sections summary,flow,functions \
  --bundle-dir ./analysis-results/raw.bundle \
  --output ./analysis-results/raw.bundle/manifest.json
```

raw architecture、base 和 entry 必须由调用者提供，不能从文件名猜测。

## 分析能力

| 任务 | 命令 |
| --- | --- |
| Aggregate triage | `report`、`analyze`、`decompile` |
| Function 与 local slice | `function`、`slice-function` |
| IL 与 CFG | `dump-il`、`dump-cfg`、`inspect-passes` |
| 静态关系 | `inspect-flow`、`call-graph`、`data-xrefs`、`aarch64-refs` |
| PE inventory | `pe-resources`、`pe-strings` |
| 语言证据 | `inspect-go`、`inspect-rust`、`inspect-types` |
| Protection evidence | `inspect-die`、`inspect-upx`、`inspect-vmp` |
| 可重复比较 | `batch`、`archive`、`replay`、`diff`、`batch-diff` |

使用 `auto-re-cli <command> --help` 查看当前安装版本的准确参数。

## 支持平台

| 主机 | 发行 target | 状态 |
| --- | --- | --- |
| macOS Apple Silicon | `macos-arm64` | 已发布；ad-hoc signed |
| macOS Intel | `macos-x86_64` | 已发布；ad-hoc signed |
| Linux x86-64 | `linux-x86_64` | 已发布 |
| Linux AArch64 | `linux-arm64` | 已发布 |
| Windows x86-64 | `windows-x86_64` | 已发布；未签名 |

macOS binary 没有 Developer ID 签名，也没有 notarization。Windows binary
支持 Windows 10 或更高版本，且没有 Authenticode 签名。

## 完整性与来源

安装前运行 `./verify.sh`。它验证：

- `SHA256SUMS` 的每一行；
- `manifest/release.json` 中所有 binary 的 target/path/size/hash；
- 精确的 managed Skill 文件集合；
- MIT-only 项目许可证边界；
- 个人 publisher 与 repository identity；
- 不含源码根、Rust 源码、私有路径、样本、内部产物以及受管控的公司/内部账号标识。

`manifest/release.json` 记录 publisher、repository URL、版本、源码 revision、
toolchain、target matrix 和 static-safety flags。第三方许可独立保存在
`THIRD_PARTY_LICENSES.md` 与 `licenses/third-party/`。

## 仓库结构

```text
bin/                         多平台 binary
skills/auto-re/              Agent Skill 与 deterministic helper
scripts/autore_distribution.py
manifest/release.json        机器可读来源
licenses/third-party/        第三方许可
SHA256SUMS                   外层完整性清单
install.sh / uninstall.sh    managed 本地安装
verify.sh                    fail-closed 发行校验器
```

## 支持

- Bug 与文档：[Issues](https://github.com/timwhitez/AutoRE-CLI/issues)
- 安全问题：[私密漏洞报告](https://github.com/timwhitez/AutoRE-CLI/security/advisories/new)
- 贡献边界：[CONTRIBUTING.md](CONTRIBUTING.md)
- 维护者：[@timwhitez](https://github.com/timwhitez)

不要上传恶意样本、恢复 payload、secret、私有路径或 proprietary analysis output。

## 许可证

AutoRE-CLI 使用 [MIT License](LICENSE-MIT)。第三方依赖保留各自许可证，其中可能
包含 Apache 许可依赖，详见 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
