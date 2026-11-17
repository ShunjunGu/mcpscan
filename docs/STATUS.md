# 立项状态（2026-11-18）

## 已完成

- [x] 生态实时查重（约 100 个关键词，`research/2026-11-18-ecosystem-dedup.md`）
- [x] 选题收敛与竞品对照（`docs/overlap.md`）
- [x] 威胁模型 25 类 → 20 规则映射（`docs/threat-model.md`）
- [x] 一页申报书（`docs/申报书.md`）
- [x] 12 天计划（`docs/PLAN.md`）
- [x] 工程骨架：`moon check --deny-warn` 零告警
- [x] 归一化层：不可见字符剥离、Unicode Tag 计数、全角折叠、UTF-16 偏移映射
- [x] 快照解析：`tools/list` JSON → `ToolDef[]`
- [x] 规则 TP001（不可见字符）、TP002（覆盖指令，中英）、TP004（敏感路径，重叠去重）
- [x] 规则 TP003（跨工具强制引用 / 隐式投毒）：三条件判定 —— 真实工具名 + 100 字符窗口强制词 + 被引用工具高权限；词边界匹配排除子串误报
- [x] 能力推断层：工具名按 `_`/`-` 切词 + schema 参数名，不使用描述文本（避免引用其他工具名污染推断）
- [x] 规则 TP006（能力隐瞒）与 TP016（只读谎报），二者互斥避免双报
- [x] 规则 TP005（外泄端点）：webhook / 短链 / OAST 域名 + 手写 IPv4 扫描
- [x] 规则 TP013（条件触发）：中英计数与信任条件
- [x] 规则 TP019（rug-pull）：SHA-256 定义指纹（覆盖 annotations）、基线写入与比对
- [x] CLI `baseline --snapshot --write`；`scan --baseline`
- [x] text / JSON / Markdown 三种报告
- [x] 41 个回归测试
- [x] 恶意 fixture（8 个工具、11 条 finding）
- [x] GitHub Actions CI 骨架

## 待办（按 PLAN）

- [ ] TP003 / TP005–TP020（17 条）
- [ ] 定义指纹 + 基线 + rug-pull（TP019）
- [ ] SARIF 2.1.0 输出
- [ ] CLI 退出码（0/1/2）
- [ ] `mcp.json` 配置解析
- [ ] 良性 fixtures ≥3，检出率/误报报告
- [ ] 真实服务器扫描 ≥3
- [ ] stdio 连接模式（可选）
- [ ] mooncakes.io 发布
- [ ] GitHub 仓库创建 + 持续提交

## 环境事实（后续排错用）

- 本机工具链：`moon 0.1.20261104`
- 包结构：库包 `src`（import 别名 `@mcpscan`），可执行包 `cmd/main`
- `pub struct` 默认只读，测试需要构造的字段用 `pub(all) struct`
- `String` 无行尾 `\` 续行；多行输出逐行 `println`
- `Array[String]::join` 不存在时用逐行输出
- `Json::as_string/as_object/as_array` 已 deprecated，改用模式匹配 `String(s)` / `Object(o)` / `Array(a)`
- `Char::from_int` 已 deprecated，改用 `Int32::unsafe_to_char`
- `StringBuilder::new()` 已 deprecated，改用 `StringBuilder()`
- `moon check` 有缓存；验证告警需 `moon clean && moon check --deny-warn`
