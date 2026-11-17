# mcpscan

**MCP 工具定义的静态安全审计器。** 在 Agent 连接一个 MCP 服务器之前，先回答一个问题：这些工具描述里，有没有试图操纵模型的文本？

```
$ mcpscan scan --snapshot tools.json
tools.json:12:5  CRITICAL  TP001  invisible-unicode     工具描述包含 37 个不可见字符（U+E0000 区块）
tools.json:12:5  CRITICAL  TP002  instruction-override 描述中出现"忽略先前指令"类覆盖语句
tools.json:12:9  HIGH      TP004  sensitive-path       描述指示读取 ~/.ssh/id_rsa
tools.json:31:3  HIGH      TP006  hidden-capability    schema 含 path 参数且名为 read_file，描述宣称只读展示
tools.json:44:1  MEDIUM    TP014  excessive-description 描述长度 4,812 字符，超出同类中位数 12 倍

5 findings (2 critical, 2 high, 1 medium) — exit 1
```

## 为什么做这个

MCP 服务器的 `tools/list` 返回自然语言描述，宿主会把它们作为**可信上下文**喂给模型。2026 年的研究已经把这条路径系统化为 25 类攻击面（描述注入、schema 字段注入、不可见 Unicode、语言切换、权限伪造、跨工具引用、rug pull、多轮升级等），并给出 `mcpvenom` 45 场景测试集。同一批研究报告了两个对工具有利的结论：

1. **纯正则描述扫描漏检 25/45 场景** —— 检测必须是多层的，不能只匹配关键词。
2. **"隐式投毒"不会调用恶意工具**：被投毒工具的描述伪造依赖（"在调用 `deleteEmail` 前必须先调用 `getEmailDetail` 做合规检查"），诱使 Agent 调用另一个合法的高权限工具。基于执行监控的方案看不到任何异常。

MoonBit 生态已有 4 个 MCP SDK 实现（`colmugx/mcp`、`moonbitstack/moonmcp`、`marianoguerra/mcp`、`shiguri-01/mcp`），但 `mooncakes.io` 上没有任何 MCP 安全审计工具；现有相关工作 `zhangbowen2006/moongate` 是**运行时网关**，需要部署代理或注入 guard，与本项目的**发布前 / 接入前静态扫描**是不同位置。

## 做什么 / 不做什么

| 做 | 不做 |
| --- | --- |
| 扫描 `tools/list` 快照、`mcp.json` 配置、stdio 连接得到的实时定义 | 运行时代理、流量拦截、工具调用审批 |
| 文本归一化（NFKC、零宽/双向控制符、Unicode Tag 解码、base64 载荷提取） | 用 LLM 判断"是否恶意"（不可复现、不可离线） |
| 20 条规则：注入、隐藏字符、敏感路径、外泄端点、能力隐瞒、schema 欺骗、仿冒、条件触发 | 事实核验、漏洞利用、自动修改第三方服务器 |
| 定义指纹与基线对比（rug pull 检测） | 替代 MCP SDK 的安全能力 |
| text / JSON / SARIF / Markdown 报告与 CI 退出码 | 商业 SaaS 上传扫描数据 |

## 快速开始

需要 MoonBit 工具链（`moon 0.1.20261104` 或更新）。

```bash
git clone https://github.com/ShunjunGu/mcpscan
cd mcpscan
moon check
moon test
moon build --target native
```

离线扫描（推荐，无需启动服务器）：

```bash
moon run cmd/main -- scan --snapshot fixtures/tools.evil.json
moon run cmd/main -- scan --snapshot tools.json --format sarif --output out/scan.sarif
```

扫描本地配置中的所有服务器：

```bash
moon run cmd/main -- scan --config mcp.json
```

基线对比（检测定义在两次发布之间是否被篡改）：

```bash
moon run cmd/main -- baseline --snapshot tools.json --write .mcpscan/baseline.json
moon run cmd/main -- scan --snapshot tools.json --baseline .mcpscan/baseline.json
```

## 检测规则

规则 id 与 2026 年 tool-poisoning taxonomy 的类别对应，详见 [`docs/threat-model.md`](docs/threat-model.md)。

| id | 名称 | 严重度 | 检测对象 |
| --- | --- | --- | --- |
| TP001 | invisible-unicode | critical | 零宽字符、双向控制符、Unicode Tag 字符、变体选择符 |
| TP002 | instruction-override | critical | "ignore previous instructions" / "忽略之前"等覆盖语句 |
| TP003 | cross-tool-reference | high | 描述强制引用其他工具（隐式投毒的核心手法） |
| TP004 | sensitive-path | critical | `~/.ssh`、`.env`、`/etc/passwd`、凭证路径 |
| TP005 | exfiltration-endpoint | high | Webhook、原始 IP、短链、非业务域名 |
| TP006 | hidden-capability | high | schema 具备写/网络/执行能力，描述未声明 |
| TP007 | schema-mismatch | medium | 描述承诺与 `inputSchema` 结构不一致 |
| TP008 | overbroad-schema | medium | `additionalProperties: true` + 诱导自由参数 |
| TP009 | typosquat | medium | 工具名与知名工具编辑距离过近 |
| TP010 | payload-splitting | high | 载荷拆分到 schema 默认值/枚举/annotation |
| TP011 | language-switch | medium | 描述中途切换语言以绕过英文规则 |
| TP012 | authority-spoofing | high | 伪造 system/admin/auditor 身份 |
| TP013 | conditional-trigger | high | "after N uses"、"once trusted"、日期条件 |
| TP014 | excessive-description | low | 超长描述稀释注意力 |
| TP015 | encoded-payload | high | 描述中的 base64/hex 大块载荷 |
| TP016 | readonly-lying | high | `readOnlyHint` 与实际参数能力矛盾 |
| TP017 | server-instruction | medium | `server/discover` 自述指令中的指令性内容 |
| TP018 | homoglyph | medium | 工具名同形异义字混淆 |
| TP019 | rug-pull | critical | 与基线的规范化定义指纹不一致 |
| TP020 | output-injection | medium | `outputSchema` 示例/描述中的注入文本 |

规则可逐条开关，配置见 [`docs/config.md`](docs/config.md)（开发中）。

## 输出

| 格式 | 用途 |
| --- | --- |
| `text` | 终端可读，默认 |
| `json` | 机器消费，稳定字段 |
| `sarif` | GitHub Code Scanning / CI 集成 |
| `markdown` | PR 评论与审计报告 |

退出码：`0` 无 finding；`1` 存在 high/critical；`2` 用法错误或读取失败。

## 与现有方案的关系

详见 [`docs/overlap.md`](docs/overlap.md)。一句话版本：

- **moongate / promptgate / aegisrun**：运行时策略执行与密钥替身。需要部署，且绕过代理后失效。本项目在部署前扫描定义，二者可组合。
- **mcp-inspector**：交互式调试器，不判断安全。
- **LAPSE / claude-hooks / theaid（生态外）**：英文规则集为主。本项目补充中文描述中的指令性语言，并提供 SARIF + 基线指纹的 CI 形态。
- **MoonDocCheck**：检查 MoonBit 包"文档准备度"，与 MCP 工具定义无关。

## 状态

v0.1.0 开发中。12 天冲刺（2026-11-18 → 2026-11-30），里程碑见 [`docs/PLAN.md`](docs/PLAN.md)。

| 能力 | 状态 |
| --- | --- |
| 归一化层（零宽 / 双向控制符 / Unicode Tag / 全角折叠） | ✅ 已实现，含偏移映射 |
| 快照解析（`tools/list` JSON） | ✅ 已实现 |
| TP001 / TP002 / TP004 | ✅ 已实现 |
| TP003（跨工具强制引用 / 隐式投毒） | ✅ 已实现，需全量工具清单 |
| TP005（外泄端点）/ TP013（条件触发） | ✅ 已实现 |
| TP006（能力隐瞒）/ TP016（只读谎报） | ✅ 已实现，共享能力推断层 |
| TP019（rug-pull / 指纹基线） | ✅ 已实现，SHA-256 指纹 + `baseline` 子命令 |
| text / JSON / Markdown / **SARIF 2.1.0** 输出 | ✅ 已实现 |
| CI 退出码（0 / 1 / 2） | ✅ 已实现，native 二进制实测 |
| 回归测试 | ✅ 41 个用例 |
| TP007–TP012 / TP014 / TP015 / TP017 / TP018 / TP020 | ⏳ 进行中 |
| `mcp.json` 配置解析 | ⏳ 进行中 |
| stdio 连接（`moonmcp` 客户端） | ⏳ D11 |

## 许可证

Apache-2.0。威胁模型参考公开发表的 MCP 安全研究，规则为本项目原创实现；不包含任何第三方规则文件的复制内容。
