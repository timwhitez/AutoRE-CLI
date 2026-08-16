# 常见问题

## AutoRE-CLI 是开源项目吗？

本仓库是 MIT 许可的公开二进制发行仓。Agent Skill、deterministic helper、
安装器、校验器、Release 自动化、受控 example 和文档在这里开源；Rust 引擎实现
没有公开。

## AutoRE-CLI 会执行被分析文件吗？

不会。产品边界是纯静态分析，不执行目标、shellcode、恢复 payload、embedded
object 或任何目标派生产物，也不使用 debugger、emulator、sandbox、DBI、JIT
或 runtime tracing。

## “证据约束”是什么意思？

输出会把直接验证的事实、有边界的推断、未解决问题和工具未声明的事实分开。
机器可读结果还包含 warning、budget、completion state、truncation、provenance
和 stop condition。

## 为什么不直接使用 Ghidra、Rizin、angr 或 capa？

这些工具解决相邻问题，并且在部分场景中是更好的选择。AutoRE-CLI 专注于预构建、
CLI-first、有边界的 JSON 契约，让人类分析师和 AI Agent 在不启动 GUI 或分析
服务的情况下使用。README 中提供了详细对比。

## 它能恢复原始源码吗？

不能。Pseudo、demangled name、source-shaped hint、recovered type 与语言证据
都是有边界的静态证据，不代表完整或与原始源码一致的恢复。

## 支持哪些输入？

公开发行支持 ELF、PE/COFF、Mach-O、universal Mach-O、object file 和明确标识
的 raw shellcode。使用 `auto-re-cli <command> --help` 查看当前版本的准确参数。

## 为什么 raw shellcode 必须提供 architecture 和 base address？

它们是调用者提供的事实，不能从文件名安全推断。AutoRE-CLI 要求显式提供，并在
后续 action 中保留这些参数。

## 可以分析恶意样本吗？

可以，但只能进行静态分析。尽量保持样本只读，把输出写入独立目录，不执行提取
内容，也不要向公开 Issue 上传样本或敏感输出。请先阅读 `SECURITY.md`。

## 安装过程会访问网络吗？

不会。下载或 clone 与安装是两个独立步骤。安装器只验证已解压发行内容，然后复制
当前平台 binary 和 Skill 文件。

## 为什么 macOS 和 Windows binary 没有完整平台签名？

macOS artifact 是 ad-hoc signed，没有 notarization；Windows artifact 没有
Authenticode 签名。Release manifest 与 SHA-256 verifier 能在可信 Release
渠道内提供完整性和来源检查，但不能替代平台代码签名。

## Agent 应该如何使用 next action？

先验证 result 或 bundle，只选择一个相关 action，检查准确 `argv[]`，并把它作为
argument vector 执行，不使用 `eval`、`sh -c` 或字符串拼接。仓库中的 helper
会强制执行这些限制。

## 在哪里报告问题？

可在 GitHub Issues 报告可复现的 CLI、安装器、校验器、Skill 或文档问题。可利用
漏洞请使用私密漏洞报告。不要附加恶意样本、恢复 payload、secret、私有路径或
proprietary analysis output。
