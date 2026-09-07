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

## 大型 Go 程序为什么只显示几个函数？

语言识别、恢复名称、发现函数、已分析函数体和当前页条目是不同数量。页已结束或
`warnings: []` 不证明全程序发现完成。检查 `inspect-go` 元数据、窗口、噪声过滤
和发现预算。存在 Go 段但没有解析出 `pclntab` 名称，表示元数据尚未解析，不能说
程序没有 Go 函数。`--limit` 只改变输出窗口，无法修复发现阶段。

## 调用图为什么在间接调用处停止？

同时查看 `unresolved_edge_count`、截断和停止原因，不能只看 warnings。通过
`function`、`dump-il`、`data-xrefs` 或 `aarch64-refs` 检查调用点。地址引用可以
提供候选，但不能单独证明调用边。已知调用者为零不等于不可达。只有深度确实限制
当前问题时才扩大深度；更大的图仍可能不完整。

## 如何处理重复动作和过大的输出？

比较输入身份、命令、选择器、页码和预算。完全相同且没有新增证据的动作应停止。
优先选择函数切片、推进的分页或支持的 spill/bundle；不要输出所有 IL 层再解析。
将 stderr、运行回执与分析 JSON 分开保存。预算耗尽后记录未解问题，不能宣告分析完成。

## 解出的可读字符串能证明行为吗？

不能。可打印字符比例和关键词评分只能排序候选，不能证明变换正确、调用关联、
端点实际使用或恶意意图。保留原始字节、编码、长度、来源地址、变换依据和冲突结果。
UTF-8 应严格校验，不能悄悄替换非法字节。不要执行样本专用模拟器或提取脚本来补证据。

## Skill 诊断为什么显示重复注册或旧版本？

记录实际解析到的 CLI 路径、版本及所有 Skill 根目录。源码/发行仓副本、已安装副本
和旧注册位置可能不同。确定目标版本后按受管安装流程更新，不能关闭检查或静默删除
其他注册。发行文档描述的是该发行版本，不一定是 PATH 当前选择的分析器。

显式检查未安装的 checkout 时，运行
`python3 skills/auto-re/scripts/skill_doctor.py --checkout --cli <checkout-cli>`。
这会将另一个已安装 Skill 与客户端重复注册区分开；已安装 Skill 仍使用常规诊断。
checkout 的 Skill 与 CLI 版本必须一致。

调用图的 next actions 带有稳定 stage，可通过 `run_next_action.py` 重放。
续查时传入 `--prior-receipt <previous.json> --receipt <new.json>`，
可以在输入、CLI、选择器与预算相同时阻止重复运行；更换输出文件名不算分析进展。
