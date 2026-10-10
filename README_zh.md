# AutoRE-CLI

[English](README.md) | [简体中文](README_zh.md)

[![Validate Distribution](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml/badge.svg)](https://github.com/timwhitez/AutoRE-CLI/actions/workflows/validate.yml)
[![Release](https://img.shields.io/github/v/release/timwhitez/AutoRE-CLI?display_name=tag)](https://github.com/timwhitez/AutoRE-CLI/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)

**面向分析师与 AI Agent 的有界纯静态逆向工程工具。**

AutoRE-CLI 把 ELF、PE/COFF、Mach-O、目标文件及明确指定的 raw 输入转换为
可追溯 JSON、CFG/IL、可读伪代码、语言与保护证据，全程不执行目标字节。

![AI 生成的概念插图：二进制输入转为结构化静态证据与有界下一步动作](assets/readme/agent-workflow-v1.png)

*AI 生成的概念插图，不是产品截图或安全认证。
具体证据流程见[流程图](assets/overview.svg)。*

[下载](https://github.com/timwhitez/AutoRE-CLI/releases/latest) ·
[安装](#安装) · [Agent 快速开始](#agent-快速开始) ·
[CLI 快速开始](#cli-快速开始) · [常见问题](FAQ_zh.md)

这里是**公开二进制发行仓与开放 Agent Skill**。引擎的 Rust 实现单独维护，
没有在本仓公开。

## 安装

需要 Python 3.9 或更高版本及[受支持的主机](#支持平台)，无需 Rust toolchain
或源码 checkout。从 [Releases](https://github.com/timwhitez/AutoRE-CLI/releases/latest)
下载适合主机的 **0.1.11** 单平台包：

```sh
tar -xzf AutoRE-CLI-0.1.11-linux-x86_64.tar.gz
cd AutoRE-CLI-0.1.11-linux-x86_64
./verify.sh
./install.sh
```

可将 `linux-x86_64` 替换为 `linux-arm64`、`macos-arm64` 或 `macos-x86_64`。
Windows 用户解压 `AutoRE-CLI-0.1.11-windows-x86_64.zip`，在解压目录打开
PowerShell 后运行：

```powershell
py -3 scripts/autore_distribution.py verify
py -3 scripts/autore_distribution.py install
```

离线安装器先验证完整发行内容，再复制 CLI 和 Skill 并记录 managed marker。
默认目录是 `$HOME/.local/bin`、`${TRAE_HOME:-$HOME/.trae}/skills/auto-re` 和
`$HOME/.agents/skills/auto-re`。将 CLI 目录加入 `PATH` 后检查
`auto-re-cli --version`。也可 clone 本仓，在仓库根运行 `./verify.sh` 和 `./install.sh`。

```sh
./install.sh --dry-run
./install.sh --cli-only
./install.sh --skill-only --agents codex
./install.sh --skill-only --agents trae
./install.sh --skill-only --agents both
./install.sh --install-dir "$HOME/bin"
./install.sh --skill-only --agents codex --codex-home "$HOME/.codex"
```

`--codex-home` 指向旧版 `<home>/skills` 兼容位置，当前默认是
`$HOME/.agents/skills`。覆盖 unmanaged 目标须显式指定 `--replace-unmanaged`。
更新时验证并安装新发行包；managed drift、同版本 binary repack、降级和额外
Skill 文件会 fail closed。`./uninstall.sh` 删除托管文件；`--force-managed` 仅允许
移除 marker 列出的已修改文件，不覆盖无关文件。
Windows 使用 `py -3 scripts/autore_distribution.py` 加相同子命令和选项。

### 其他安装入口

包管理器只安装 CLI。本仓包含版本化 [Scoop manifest](https://github.com/timwhitez/AutoRE-CLI/blob/main/packaging/scoop/autore-cli.json)
和 [Homebrew formula](https://github.com/timwhitez/AutoRE-CLI/blob/main/packaging/homebrew/autore-cli.rb)。独立 Homebrew Tap 发布前，
请使用已验证的单平台包；包管理器可用时间可能晚于发行时间。

```powershell
scoop install https://raw.githubusercontent.com/timwhitez/AutoRE-CLI/main/packaging/scoop/autore-cli.json
```

仅安装 Skill 到 Codex、Claude Code、Cursor 等受支持客户端：

```sh
npx skills add \
  https://github.com/timwhitez/AutoRE-CLI/releases/download/v0.1.11/AutoRE-CLI-0.1.11-auto-re-skill.zip -g
```

保持已安装 CLI 与 Skill 版本一致。下载或包管理器联网与离线安装器是不同步骤。

## Agent 快速开始

安装后刷新 Agent，调用 [`auto-re` Skill](skills/auto-re/SKILL.md)：

```text
使用 $auto-re 对 ./samples/sample.exe 进行纯静态分析，将有界、可追溯的结论
写入 ./analysis-results。不得执行样本或任何目标派生产物。
```

直接获取第一份证据时，使用已安装 Skill。输入放在 `./samples/`；结果必须在输入
解析后父目录及其所有子目录之外，也必须在 Skill 目录之外。结果父目录须已存在，
结果子目录须为新路径。

```sh
mkdir -p ./analysis-results
python3 "$HOME/.agents/skills/auto-re/scripts/skill_doctor.py"
python3 "$HOME/.agents/skills/auto-re/scripts/start_analysis.py" \
  ./samples/sample.exe --result-dir ./analysis-results/first-pass
```

Windows 使用 `py -3`，参见[平台调用](skills/auto-re/references/platform-invocation.md)。
启动器要求已安装 CLI/Skill 配对通过就绪检查；unmanaged checkout 使用
[Skill](skills/auto-re/SKILL.md) 中的显式流程。

阅读返回的 **`result_path`**，检查 warning、预算、completion 和 `next_actions[]`。
启动器摘要与操作 receipt 不构成分析结论，进程退出码为零也不证明分析完整。

窄问题直接选择一个入口，无需先跑总报告：

```sh
# 精确函数：--addr 与 --symbol 互斥
python3 "$HOME/.agents/skills/auto-re/scripts/start_analysis.py" \
  ./samples/sample.exe --addr 0x401000 --result-dir ./analysis-results/function-pass

# PE 字符串清单；其他支持的 inspection 见 --help
python3 "$HOME/.agents/skills/auto-re/scripts/start_analysis.py" \
  ./samples/sample.exe --command pe-strings --result-dir ./analysis-results/strings-pass
```

高级分页、引用查询和续查见[命令路由](skills/auto-re/references/command-routing.md)。
先明确尚未回答的问题，验证 bundle/spill，每次只跟进一个相关静态动作。
用 `run_next_action.py --dry-run` 检查 emitted `argv[]`，续查保留 receipt 并传入
`--prior-receipt`。证据足够、预算耗尽、语义不支持或相同请求没有进展时停止。

## CLI 快速开始

无需打开输入即可查询命令契约：

```sh
auto-re-cli describe --format json
auto-re-cli describe --format json --command function
```

创建有界报告 bundle 并验证 payload：

```sh
mkdir -p ./analysis-results/receipts
auto-re-cli report ./samples/sample.exe \
  --format json --json-profile ai \
  --sections binary,summary,inspections,flow,functions,types --limit 8 \
  --bundle-dir ./analysis-results/sample.bundle \
  --output ./analysis-results/sample.bundle/manifest.json

python3 "$HOME/.agents/skills/auto-re/scripts/verify_bundle.py" \
  ./analysis-results/sample.bundle/manifest.json \
  --receipt ./analysis-results/receipts/bundle-verification.json
```

读取 receipt 的 `files[].path`：它们指向稳定、哈希已验证的只读副本。
最后一个消费者结束后，只清理校验器拥有的临时树：

```sh
python3 "$HOME/.agents/skills/auto-re/scripts/verify_bundle.py" \
  --cleanup-receipt ./analysis-results/receipts/bundle-verification.json
```

聚焦函数及 CUSTOM IL：

```sh
auto-re-cli function ./samples/sample.exe --addr 0x401000 \
  --format json --output ./analysis-results/function-401000.json
auto-re-cli dump-il ./samples/sample.exe --level custom --addr 0x401000 \
  --format json --output ./analysis-results/custom-il-401000.json
```

分析 raw shellcode 须显式传入 `--raw-shellcode --arch x86 --base-address 0x1000`
及已知的 `--entry-address`，不能从文件名推断架构、基址或入口。
独立编写的无害目标文件示例见[受控 Demo](https://github.com/timwhitez/AutoRE-CLI/blob/main/examples/controlled/README.md)。
其记录属于历史 fixture 证据，不代表当前质量或全程序覆盖率。

## 分析入口与 0.1.11

| 任务 | 命令 |
| --- | --- |
| Triage 与伪代码 | `report`、`analyze`、`decompile` |
| 精确函数与切片 | `function`、`function-bounds`、`slice-function` |
| IL 与 CFG | `dump-il`、`dump-cfg`、`inspect-passes`；实验性 `dump-llvm` |
| 静态关系 | `inspect-flow`、`call-graph`、`data-xrefs`、`aarch64-refs` |
| PE 清单 | `pe-resources`、`pe-strings` |
| 语言与保护证据 | `inspect-go`、`inspect-rust`、`inspect-types`、`inspect-die`、`inspect-upx`、`inspect-vmp` |
| 静态字节恢复 | `recover-bytes`、`fold-pair-bytes`（有界数据变换，不执行目标） |
| 归档与比较 | `batch`、`archive`、`replay`、`batch-replay`、`diff`、`batch-diff`、`compare-functions` |
| 测量 | `bench`（需记录输入及可比测量） |

0.1.11 新增 metadata-only `describe`、通过全局 `--diagnostic-format json` 选择
有界 stderr 错误，以及八个指定命令可选的 `--result-contract kinds-v1`。
默认文本错误和 `legacy` 结果根仍可使用。通过 `describe` 与 `<command> --help`
查询支持的选项，使用配对的 0.1.11 Skill 消费新结果根。Skill 还支持精确有界的
对象键分页、Unicode 字符串切片及请求身份/no-progress 检查。

## 限制与证据

- 分析架构为 x86、x86-64 和 AArch64；覆盖程度取决于容器、元数据、指令支持和预算。
- 伪代码及 Go/Rust source-shape 提示属于静态证据，不是原始源码。不宣称完整源码
  语义、通用语言 ABI 恢复或全程序可达性；不支持的语义保持显式。
- UPX/VMProtect 检测不等于完整脱壳或去虚拟化。可信静态 helper 须显式 opt-in，
  helper 产物仍是数据。
- 完成一页、warning 为空或零名称/调用者都不能证明完整性或不可达。一起检查截断、
  unresolved edge 与 stop reason。`--limit` 控制输出行，discovery 与输入预算另计，
  不限制 peak memory；默认输入快照预算为 256 MiB。
- 字符串、名称和推断角色不证明运行时行为、恶意意图或作者身份。区分
  `validated`、`inferred`、`unresolved` 和 `not_claimed`。

AutoRE-CLI 适用于预构建 CLI 自动化与有界 Agent 证据。Ghidra/Rizin 面向交互式
框架工作流，capa 面向规则型能力分析，Ghidra MCP 集成操作现有 Ghidra 环境。
AutoRE-CLI 不提供 debugger、emulator、sandbox、符号执行或分析服务。

## 支持平台

| 主机 | 发行 target | 签名 |
| --- | --- | --- |
| macOS Apple Silicon | `macos-arm64` | Ad-hoc signed |
| macOS Intel | `macos-x86_64` | Ad-hoc signed |
| Linux x86-64 | `linux-x86_64` | 不适用 |
| Linux AArch64 | `linux-arm64` | 不适用 |
| Windows x86-64（Windows 10+） | `windows-x86_64` | 未签名 |

macOS 没有 Developer ID 签名或 notarization；Windows 没有 Authenticode 签名。
Linux 发行版使用动态链接 GNU target。主机平台矩阵与被分析输入架构不同。

## 完整性与公开边界

安装前运行 `./verify.sh` 或 Windows Python 等价命令。它检查准确的 `SHA256SUMS`
文件集合、binary target/size/hash、托管 Skill 清单、publisher 身份、许可边界及
禁止的私有内容。[manifest/release.json](manifest/release.json) 将二进制绑定到原始
源码 revision、toolchain、版本及签名状态。校验和不替代平台签名，也不证明输入安全。

本 MIT 发行仓包含二进制、开放 Skill/helper、安装器、校验器、自动化、受控 Demo
源码、图片和文档。Rust 引擎实现、私有规格、样本与分析输出没有公开。
这里的“开源”适用于公开脚本、Skill、示例、自动化和文档。

## 维护与支持

[FAQ](FAQ_zh.md) · [调查流程](skills/auto-re/references/investigation-workflows.md) ·
[发行历史](https://github.com/timwhitez/AutoRE-CLI/blob/main/CHANGELOG.md) · [贡献指南](CONTRIBUTING.md) ·
[维护说明](AGENTS.md) · [@timwhitez](https://github.com/timwhitez)

通过 [Issues](https://github.com/timwhitez/AutoRE-CLI/issues) 报告 bug 或文档问题，
通过 [Discussions](https://github.com/timwhitez/AutoRE-CLI/discussions/1) 讨论用例，
安全缺陷使用[私密漏洞报告](https://github.com/timwhitez/AutoRE-CLI/security/advisories/new)。
不要上传恶意样本、payload、secret、私有路径或 proprietary analysis output。

项目采用 [MIT License](LICENSE-MIT)。第三方依赖保留各自许可，包括适用的
Apache 许可，详见[第三方声明](THIRD_PARTY_LICENSES.md)。
