# 竞品与相邻项目对照

日期：2026-11-18。检索范围：`mooncakes.io` 注册表 API（约 100 个关键词）+ 公开的 MCP 安全研究。本文只做定位比较，不做效果排名；所有"已覆盖"判断来自公开 README/API，未逐项运行验证。

## 结论

**MoonBit 生态内没有 MCP 工具定义的静态审计工具。** `tool poisoning` 关键词在注册表 0 命中；`mcp security` 的 8 条命中全部是运行时网关、策略执行或 SDK 自身。

**生态外有同类工具，但形态不同**：多数是商业 SaaS、Claude Code hook 或运行时中间件，没有"离线 + SARIF + 基线指纹 + 可嵌入 MoonBit 库"的组合。

## 一、MoonBit 生态内

| 项目 | 形态 | 已有能力 | 与本项目关系 |
| --- | --- | --- | --- |
| `zhangbowen2006/moongate` 0.7.1 | 运行时 MCP 安全网关 | 双执行点策略、密钥替身、路径逃逸拦截、会话配额、一次性审批、哈希链账本 | **位置不同**：它在工具执行前拦截；本项目在服务器接入前审计定义。其 README 自述"MCP 安全网关在 2026 年已是拥挤赛道"，并列出 MCP Shield / MCPKernel / MCPGuard / taintmcp / AgentPerms / Authsome 等；本项目不做网关 |
| `zyyaa125/promptgate` 0.1.0 | Prompt 门禁 | 面向 agent 的 prompt 安全门禁 | 处理运行时输入，不扫描工具定义 |
| `zhangbowen2006/agentcanary` 0.1.1 | Agent 安全（细节未核实） | — | 需在实现阶段复核，避免规则重叠 |
| `doffice/moonpermit` 0.1.1 | 权限（细节未核实） | — | 运行时权限模型 |
| `tuya-me/aegisrun` 0.9.3 | Agent 安全工具运行时 | MoonBit + Wasm 的工具运行时 | 注册表 `build_status=failed`，不计入可用供给；形态是运行时 |
| `moonbitstack/moonmcp` 0.2.1 | MCP SDK（服务端+客户端） | conformance 全过、OAuth、速率限制、中间件、telemetry | **可复用为连接层**：`Client::connect` + `list_tools` 可在实现阶段用于 stdio 扫描模式 |
| `colmugx/mcp` 0.18.2 | MCP SDK | 9890 下载、34 版本、JSON Schema 校验 | 备选连接层；其 schema validator 可作对照，但不是安全审计 |
| `gywcs101/MoonDocCheck` 0.1.0 | MoonBit 文档准备度检查 | API 注释覆盖率、README、示例标记、元数据、CI 信号 | 检查对象是"包文档"，不是 MCP 工具定义；无重叠 |
| `Mr-Houjie/mbt-typeset` 0.1.0 | 中文排版校对 | 30 条规则、自动修复、CI 输出 | 领域不同；但其"生态查重 + 定位说明"的写法是本项目申报的参照 |

## 二、MoonBit 生态外（公开研究/工具）

| 工具/研究 | 形态 | 已有能力 | 本项目的差异 |
| --- | --- | --- | --- |
| Lasso Security `claude-hooks`（2026-01） | Claude Code hook | 50+ 模式检测 | 绑定单一宿主；本项目是独立 CLI + 库，输出 SARIF |
| `theaid` scanner（2026-02） | 扫描器（细节未核实） | — | 非 MoonBit；本项目提供 MoonBit 原生实现与库嵌入 |
| Apify MCP Poisoning Scanner | 商业 API 服务 | 在线扫描 | 需上传定义到第三方；本项目离线，定义不出本机 |
| `mcpvenom`（研究套件） | 攻击测试集 | 45 场景、25 类 | 是攻击生成器，不是防御工具；本项目将其核心场景转写为防御测试 fixtures |
| MCP Shield / MCPKernel / MCPGuard / taintmcp | 运行时 | 策略、污点、审批 | 同 moongate：运行时位置，本项目在其之前 |
| `mcp-inspector`（`marianoguerra`） | 交互式调试 | 会话、capability、catalog | 不判断安全，只展示 |

## 三、为什么不是"给现有项目提 PR"

1. **位置不同**：moongate 等是运行时网关，需要部署代理或注入 guard；静态审计发生在部署前与 CI 中，两者可串联（本项目输出可直接作为网关策略的输入候选）。
2. **宿主不同**：`claude-hooks` 绑定 Claude Code；本项目是语言级库 + CLI，任何 MoonBit 宿主（moonmcp / posoco / 自研）都能调用。
3. **数据流向不同**：商业扫描器要求上传定义；本项目的离线模式不发起网络请求，适合企业内网与私有 MCP 服务器。
4. **交付形态不同**：SARIF + 基线指纹 + 退出码是 CI 门禁的三件套，现有 MoonBit 项目没有任何一个提供。

## 四、检索方法与局限

- 查询：`https://mooncakes.io/api/v0/search?kw=<keyword>&limit=50`，关键词包括 `mcp security`、`tool poisoning`、`agent security`、`llm security`、`prompt audit`、`guardrail`、`audit`、`sbom`、`license audit` 等约 100 个。
- `limit=50` 有效，`page`/`offset` 不翻页；无法保证拿到第 50 条之后的命中。
- 只核对 README/API 声称的能力，未 clone 运行；`build_status` 仅代表注册表构建状态。
- 未穷举未发布到 mooncakes 的 GitHub/GitLink 私有项目。
- 生态外工具的能力描述来自公开博客与论文摘要，未做独立复现。

*关联文档：[`threat-model.md`](threat-model.md) · [`申报书.md`](申报书.md)*
