# 立项状态（2026-11-18）

## 仓库与 CI

| 项目 | 状态 |
| --- | --- |
| 远端仓库 | https://github.com/ShunjunGu/mcpscan（public） |
| 提交 | 15 个，按能力单元分批 |
| CI | GitHub Actions **全绿** |

CI 覆盖：`moon update` → `moon check --deny-warn` → `moon test` → `moon build --target native`，随后直接运行二进制验证：

- 恶意 fixture → exit 1
- 良性 fixture → exit 0
- 读取失败 → exit 2
- SARIF 2.1.0 结构校验
- 基线写入 + 同快照比对回路

## 已完成

- [x] 生态实时查重（约 100 个关键词，`research/2026-11-18-ecosystem-dedup.md`）
- [x] 选题收敛与竞品对照（`docs/overlap.md`）
- [x] 威胁模型 25 类 → 20 规则映射（`docs/threat-model.md`）
- [x] 一页申报书（`docs/申报书.md`）
- [x] 12 天计划（`docs/PLAN.md`）
- [x] 工程骨架：`moon check --deny-warn` 零告警
- [x] 归一化层：不可见字符剥离、Unicode Tag 计数、全角折叠、UTF-16 偏移映射
- [x] 快照解析：`tools/list` JSON → `ToolDef[]`
- [x] 检测规则 9 条：TP001 / TP002 / TP003 / TP004 / TP005 / TP006 / TP013 / TP016 / TP019
- [x] 能力推断层：工具名按 `_`/`-` 切词 + schema 参数名，不使用描述文本
- [x] TP019：SHA-256 定义指纹（覆盖 annotations）、基线写入与比对
- [x] CLI `baseline --snapshot --write`；`scan --baseline`
- [x] 报告：text / JSON / Markdown / SARIF 2.1.0
- [x] CI 退出码 0 / 1 / 2（native 二进制实测）
- [x] 41 个回归测试
- [x] 恶意 fixture（8 个工具、11 条 finding）与良性 fixture（3 个工具、0 finding）
- [x] GitHub Actions 全绿

## 待办

- [ ] 规则 TP007–TP012 / TP014 / TP015 / TP017 / TP018 / TP020（11 条）
- [ ] `mcp.json` 配置解析
- [ ] 真实服务器扫描 ≥3，产出检出率/误报报告
- [ ] stdio 连接模式（可选）
- [ ] `mooncakes.io` 发布
- [ ] 报名表中填写仓库地址与申报书

## 环境事实（后续排错用）

- 本机工具链：`moon 0.1.20261104`
- 包结构：库包 `src`（import 别名 `@mcpscan`），可执行包 `cmd/main`
- `pub struct` 默认只读，测试需要构造的字段用 `pub(all) struct`；enum 同理用 `pub(all) enum`
- 泛型写 `Array[T]`，不是 `Array<T>`（后者会被解析为比较运算）
- `String` 无行尾 `\` 续行；多行输出逐行 `println`
- `Json::as_string/as_object/as_array` 已 deprecated，改用模式匹配 `String(s)` / `Object(o)` / `Array(a)`
- `Char::from_int` 已 deprecated，改用 `Int32::unsafe_to_char`
- `StringBuilder::new()` 已 deprecated，改用 `StringBuilder()`
- String → Bytes 用 `@utf8.encode`（`moonbitlang/core/encoding/utf8`），不是 `to_bytes`
- SHA-256 在 `moonbitlang/x/crypto`（`@crypto.sha256` + `@crypto.bytes_to_hex_string`）
- `String::split` 返回 `StringView`，需要 `.to_owned()`
- function 末尾直接写 `{ field, ... }` 会被当成代码块，需要 `return { ... }`
- `match` 分支里直接跟 `for` 需要包 `{ }` 块
- `moon run` 会掩盖进程真实退出码；验证退出码必须直接运行 `_build` 下的二进制
- MoonBit native 后端在 Linux 上也产出 `main.exe` 后缀，CI 中需动态定位
- `moon check` 有缓存；验证告警需 `moon clean && moon check --deny-warn`
