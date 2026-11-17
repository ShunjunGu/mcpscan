# 生态查重记录：MCP 工具投毒审计器

- 日期：2026-11-18
- 对象：`mcpscan` 选题（MCP 工具定义静态审计）
- 方法：`mooncakes.io` 注册表 API v0 实时检索 + 公开安全研究检索
- 查询形态：`https://mooncakes.io/api/v0/search?kw=<keyword>&limit=50`

## 一句话结论

**MoonBit 生态内没有 MCP 工具定义的静态审计工具。** `tool poisoning` 0 命中；`mcp security` 的 8 条命中全部是运行时网关、策略执行或 MCP SDK。同类能力在生态外存在，但形态（商业 SaaS / Claude Code hook / 运行时中间件）与本项目（离线 CLI + SARIF + 基线指纹 + MoonBit 库）不重叠。

## 一、直接相关方向

| 关键词 | 命中数 | 相关包 | 判定 |
| --- | ---: | --- | --- |
| `tool poisoning` | 0 | — | **空白** |
| `mcp security` | 8 | `moongate` 0.7.1、`aegisrun` 0.9.3（build failed）、`moonapi`、`moonmcp` | 运行时，非静态审计 |
| `agent security` | 18 | `promptgate` 0.1.0、`moongate`、`agentcanary` 0.1.1、`moonpermit` 0.1.1 | 运行时/prompt 门禁 |
| `llm security` | 9 | `moonprompt`、`promptgate`、`mooncake-audit` 0.4.1、`mizchi/sandbox` | 无工具定义扫描 |
| `prompt injection` | 16（Nov_1 记录） | 均为间接提及 | 无检测实现 |
| `guardrail` | 8（Nov_1 记录） | A/B 测试或规则引擎 | 无 LLM 内容护栏 |
| `sbom` | 5 | `cogna-dev/sbom`、`moonseal`、`moon_purl`、`moonvigil` | 供应链，非 MCP |
| `license audit` | 15 | `moonbit-license-audit`、`depsight` | 许可证，非 MCP |

**关键竞品边界**：`zhangbowen2006/moongate` 0.7.1（68 下载、7 版本、47 单测 + 21 Node 测试）是运行时 MCP 安全网关——双执行点策略、密钥替身、路径逃逸拦截、审批、哈希链账本。它明确自述"MCP 安全网关在 2026 年已是拥挤赛道"。本项目不做网关，在工具定义进入宿主**之前**做静态审计，输出可作为网关策略的输入候选。

## 二、为确认"是否已有替代"而扩展检索的方向

以下方向与本项目无直接关系，检索目的是确认生态整体饱和度，避免误判"空白"。

| 方向族 | 关键词 | 结果 |
| --- | --- | --- |
| 压缩/编码 | `deflate`、`zlib`、`zstd`、`brotli`、`lz4`、`crc32`、`blake3`、`sha256` | 全部有 3+ 实现（`gaato/deflate`、`moonbit-community/flate`、`mizchi/zlib`、`gaato/zstd`、`mizchi/brotli`、`gaato/lz4`） |
| 归档 | `zip`、`tar` | `bobzhang/zip`、`gaato/zip`、`bobzhang/tar` |
| 图像/字体/PDF | `png`、`jpeg`、`font`、`svg`、`pdf` | `gaato/png`、`mizchi/image`、`moonbitstack/moonimage`、`moonbitlang/pdflite`、`moonbitlang/pagelayout` |
| 办公/数据 | `xlsx`、`csv`、`json schema`、`openapi`、`graphql` | `moonbitlang/mbtexcel`、`mizchi/jsonschema`、`Atman-Angle/oas2moon`（4 包）、`moonbitstack/moongql` |
| 工程基础设施 | `rate limit`、`circuit breaker`、`retry`、`feature flag`、`tracing`、`metrics`、`logging` | `moonbitstack/moonward`、`liying-han/moonresilience`、`moonbitstack/moontel`、`moonbit-community/metrics` |
| 测试工具 | `mutation testing`、`snapshot test`、`fuzz`、`property testing`、`coverage` | `Magic486/moon_mutest`、`moonbitlang/quickcheck`、`moonbitlang/moon_cove`、`weopqrst/mooncassette` |
| 文档工具 | `markdown lint`、`doc drift`、`api documentation` | `Mr-Houjie/mbt-typeset`（中文排版）、`gywcs101/MoonDocCheck`（文档准备度）；`doc drift` 0 命中 |
| 协议/格式 | `jsonpath`、`jmespath`、`msgpack`、`cbor`、`semver`、`icalendar`、`rfc 5545`、`idna`、`bidi`、`url parse` | 全部有实现 |
| 数据库/网络 | `redis`、`postgres`、`sqlite`、`websocket`、`kafka` | 全部有 3+ 实现 |

**结论**：MoonBit 生态在 2026-11 已高度饱和，"经典库"方向基本无空白。本项目的差异不来自"没人做过 MCP"，而来自"没人做过 MCP 工具定义的静态审计"——一个由 2026 年攻击研究催生的新位置。

## 三、生态外同类工具

| 工具 | 形态 | 与本项目的差异 |
| --- | --- | --- |
| Lasso Security `claude-hooks`（2026-01） | Claude Code hook，50+ 模式 | 绑定单一宿主；本项目独立 CLI + 库 + SARIF |
| `theaid` scanner（2026-02） | 扫描器 | 非 MoonBit；无库嵌入形态 |
| Apify MCP Poisoning Scanner | 商业 API | 需上传定义；本项目离线 |
| `mcpvenom`（研究） | 45 场景攻击生成器 | 是攻击套件，不是防御工具；本项目将其场景转写为 fixtures |
| MCP Shield / MCPKernel / MCPGuard / taintmcp | 运行时 | 运行时位置，与本项目互补 |

## 四、研究依据（威胁模型）

- *MCP Tool Poisoning in Agentic AI Frameworks: A Cross-Framework Measurement Study*（2026）：25 类 taxonomy、45 场景 `mcpvenom`；**正则扫描漏检 25/45**。
- *Implicit Tool Poisoning / Uninvoked Tool Metadata Hijack*（2026）：投毒工具不被调用，通过伪造跨工具依赖诱导调用合法高权限工具。
- *Hidden Unicode Instruction Injection in AI Agent Skills*（CSA Labs，2026）：Unicode Tag、零宽字符、HTML 注释、base64 载荷。
- *Security Analysis of the MCP Ecosystem*（2026）：协议面扩展（`CacheableResult`、`server/discover`、`x-mcp-header`）带来的新攻击面。

## 五、检索局限

1. `mooncakes` 搜索只匹配包名、keywords 与自动摘要；中文关键词不被索引（Nov_1 已实测 20 个中文词全部 0 命中）。本次只用英文关键词。
2. `limit=50` 有效，`page`/`offset` 不翻页；无法保证覆盖第 50 条之后。
3. 只核对 README/API 声称的能力，未 clone 运行；`build_status` 仅代表注册表构建状态。
4. 未穷举未发布到 mooncakes 的 GitHub/GitLink 私有项目。
5. 生态外工具的能力描述来自公开博客/论文摘要，未独立复现。
6. "空白"仅指上述检索范围内未发现可消费的同类包，不等于"不存在任何实现"。

---

*关联：[`../docs/overlap.md`](../docs/overlap.md) · [`../docs/threat-model.md`](../docs/threat-model.md)*
