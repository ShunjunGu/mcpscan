# 威胁模型：MCP 工具投毒的分类与规则映射

本文件把公开发表的 25 类 tool-poisoning 分类映射到本项目的 20 条规则，并明确**不在静态检测范围内**的类别。映射目的是可解释：每条 finding 都能回答"它对应哪种攻击手法、依据是什么、哪里检测不到"。

## 一、攻击面：模型看到的文本

MCP 的 `tools/list` 返回结构大致为：

```json
{
  "name": "read_file",
  "description": "...",
  "inputSchema": { "type": "object", "properties": { ... }, "required": [...] },
  "outputSchema": { ... },
  "annotations": { "title": "...", "readOnlyHint": true, "destructiveHint": false }
}
```

宿主把这些字段整体序列化进模型上下文。**任何进入上下文的字符串都是攻击面**，不只是 `description`。载荷可以出现在：

| 载体 | 说明 | 本项目是否覆盖 |
| --- | --- | --- |
| `description` | 最常见载体 | ✅ TP001–TP020 |
| `inputSchema.properties[*].description` | 参数级描述 | ✅ |
| `inputSchema.properties[*].enum` / `default` | 枚举与默认值中的指令 | ✅ TP010 |
| `inputSchema.properties[*].title` | 参数标题 | ✅ |
| `outputSchema` | 输出示例中的指令 | ✅ TP020 |
| `annotations.title` / 其他 annotation 字符串 | 易被忽略 | ✅ TP010 |
| server instructions（`server/discover` 自述） | 服务器级指令 | ✅ TP017（快照含该字段时） |
| tool result（运行时） | 工具执行输出 | ❌ 运行时数据，静态模式无法获得 |
| 服务器业务逻辑 | 定义良性但实现恶意 | ❌ 需代码审计/运行监控 |
| 多轮会话升级 | 会话状态驱动 | ❌ 需运行时状态 |

## 二、25 类 → 规则映射

分类编号来自 *MCP Tool Poisoning in Agentic AI Frameworks: A Cross-Framework Measurement Study*（2026）的 taxonomy（P1–P25）。本项目的规则不是逐条抄写，而是按**可静态检测的证据类型**重新组织。

| taxonomy | 类别 | 本项目规则 | 静态可检测性 |
| --- | --- | --- | --- |
| P1 | 直接描述注入 | TP002 instruction-override | ✅ 高 |
| P2 | schema 字段注入 | TP010 payload-splitting、TP007 schema-mismatch | ✅ 高 |
| P3 | 不可见/编码载荷 | TP001 invisible-unicode、TP015 encoded-payload | ✅ 高（归一化后可判定） |
| P4 | 语言切换 | TP011 language-switch | ⚠️ 中（依赖语言检测启发式） |
| P5 | 权限伪造 | TP012 authority-spoofing | ✅ 高 |
| P6 | 工具结果注入 | — | ❌ 运行时 |
| P7 | 跨工具引用 | TP003 cross-tool-reference | ✅ 高 |
| P8 | rug-pull / 重定义 | TP019 rug-pull | ✅ 高（需基线） |
| P9 | 多轮升级 | TP013 conditional-trigger（部分） | ⚠️ 低（仅静态痕迹） |
| P10 | confused deputy | TP006 hidden-capability、TP016 readonly-lying | ⚠️ 中（推断能力声明） |
| P11 | 跨 Agent 注入 | TP003（部分） | ⚠️ 低 |
| P12 | 条件/触发载荷 | TP013 conditional-trigger | ✅ 中高 |
| P13 | 载荷拆分 | TP010 payload-splitting | ✅ 中高 |
| P14 | resource 注入 | TP017 server-instruction（resource 描述） | ⚠️ 中 |
| P15 | prompt 注入（MCP prompt 模板） | TP017（快照含 prompts 时） | ⚠️ 中 |
| P16 | annotation 注入 | TP010、TP016 | ✅ 高 |
| P17 | Unicode 隐写 | TP001 | ✅ 高 |
| P18 | 流式注入 | — | ❌ 运行时 |
| P19 | 版本降级 | TP019（指纹变更的一种） | ⚠️ 中 |
| P20 | 参数绑定 | TP007 schema-mismatch | ⚠️ 中 |
| P21 | 通知注入 | — | ❌ 运行时 |
| P22 | 语义遮蔽 | TP009 typosquat、TP018 homoglyph | ✅ 中 |
| P23 | 长上下文稀释 | TP014 excessive-description | ✅ 高（可度量） |
| P24 | 跨阶段持久化 | — | ❌ 运行时 |
| P25 | 动态注册 | TP019（定义集合变化） | ⚠️ 中 |

**统计**：完全静态可检 11 类，部分可检 9 类，明确不可检 5 类。报告头部必须披露这一比例——不承诺"检测所有投毒"。

## 三、20 条规则定义

严重度只表示该模式在已发表攻击中的**危险性**，不表示目标服务器已被攻陷或该模式必然恶意。

| id | 名称 | 严重度 | 判定依据 | 已知误报条件 |
| --- | --- | --- | --- | --- |
| TP001 | invisible-unicode | critical | 存在 U+200B–U+200F、U+202A–U+202E、U+2060–U+206F、U+E0000–U+E007F、变体选择符 | 正常的 emoji ZWJ 序列；需白名单 |
| TP002 | instruction-override | critical | 归一化文本命中覆盖句式（中英） | 安全文档中引用攻击示例 |
| TP003 | cross-tool-reference | high | 描述中出现**真实存在**的其他工具名 + 100 字符窗口内的强制/时序词 + 被引用工具具备高权限语义（写/删除/执行/网络） | 合法的"必须先调 X 再调 Y"工作流文档；只读工具被引用不报 |
| TP004 | sensitive-path | critical | `~/.ssh`、`.aws`、`.env`、`/etc/passwd`、`id_rsa`、凭证类路径 | 合法的凭证管理工具 |
| TP005 | exfiltration-endpoint | high | 已知 webhook / 短链 / OAST 域名（webhook.site、ngrok、burpcollaborator、oast.* 等）与 IPv4 字面量；域名用词边界匹配 | 合法的 webhook 集成工具；内网文档示例地址 |
| TP006 | hidden-capability | high | 工具名 token（按 `_`/`-` 切词）或 schema 参数名显示写/删除/执行/网络能力，且描述中未出现对应能力词；`readOnlyHint=true` 时让位给 TP016 | 描述使用词表外的近义词；参数名通用（`data`） |
| TP007 | schema-mismatch | medium | 描述承诺的字段集合与 `required`/`properties` 不一致 | 描述用自然语言、难以完全对齐 |
| TP008 | overbroad-schema | medium | `additionalProperties: true` 且存在自由字符串参数 + 指令性描述 | 通用透传工具 |
| TP009 | typosquat | medium | 工具名与内置知名工具集编辑距离 ≤2 且非同名 | 合法近似命名 |
| TP010 | payload-splitting | high | 指令片段分布在 description + enum/default/title 中，单独看均不完整 | 多语言文档 |
| TP011 | language-switch | medium | 描述主体语言与结尾指令语言不一致，且切换段落含指令词 | 双语项目 |
| TP012 | authority-spoofing | high | "system"、"administrator"、"security audit" 等身份声明 + 指令 | 合法帮助文本 |
| TP013 | conditional-trigger | high | "after N uses / calls"、"once trusted / after trust is established"、"使用 N 次后"、"信任建立后"、"达到 N 次"等计数或信任条件 | 业务工具的限流说明；纯日期条件未实现，列入覆盖缺口 |
| TP014 | excessive-description | low | 描述长度 > 2,000 字符或超过同批中位数 8 倍 | 复杂工具的正常长文档 |
| TP015 | encoded-payload | high | 连续 base64/hex 长度 ≥ 80 且解码后可打印比 > 0.8 | 内嵌证书/密钥样例 |
| TP016 | readonly-lying | high | `readOnlyHint=true` 且工具名 token 或 schema 参数名显示 mutating 能力（写/删除/执行/网络） | annotation 填写不准确但实现确实只读 |
| TP017 | server-instruction | medium | server instructions / prompt 模板含指令性语句 | 正常的服务器使用说明 |
| TP018 | homoglyph | medium | 工具名含拉丁/西里尔/希腊混排同形字符 | 国际化命名 |
| TP019 | rug-pull | critical | 规范化定义指纹（名称+描述+两 schema+annotations 的 SHA-256）与基线不一致 → critical；基线中不存在的新工具 → high；基线中有而本次消失 → medium | 正常的版本升级；需人工确认后更新基线 |
| TP020 | output-injection | medium | `outputSchema` 的描述/example 含指令性文本 | 示例数据本身含命令 |

## 四、检测原则

1. **先归一化，再匹配**：所有规则作用于归一化文本；报告引用原始区间，保证可定位。
2. **证据优先于结论**：finding 必须带原文片段与规则 id；不输出"该服务器恶意"的整体判断。
3. **fail-closed 的边界**：基线比对失败（文件缺失/格式错误/指纹不匹配）默认按 critical 处理，除非显式 `--allow-baseline-miss`。
4. **可解释的漏报**：每条规则在测试集中必须有反例；未覆盖类别写入报告头部。

## 五、不在范围内

- **工具执行结果投毒**：需要运行时代理，属 `moongate` 等网关的领域。
- **服务器业务逻辑后门**：定义可以完全良性，恶意在实现里；需代码审计或运行时监控。
- **依赖供应链**：npm/PyPI 包投毒不在本工具范围；已有 `moon_guard`、SBOM 类工具处理 MoonBit 侧。
- **多轮会话升级**：需要会话状态，静态快照拿不到。
- **LLM 语义级判断**：本项目刻意不做；不可复现、不可离线、不可解释。

---

*参考来源见 [`overlap.md`](overlap.md) 第二节；攻击分类的原始论文与报告链接见仓库 `research/`。*
