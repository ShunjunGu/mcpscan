// 核心数据模型。设计约束：
// 1. 扫描单位是完整工具定义，不是单个描述字段——载荷可以放在 schema 的
//    默认值、枚举、annotation 的标题里。
// 2. 每条发现必须能回到原始文本的字节偏移，报告才能定位。
// 3. 严重度描述的是"该模式在已发表攻击中的危险性"，不是目标服务器的信誉。

///|
/// 发现的分级。`Critical` 不表示服务器已被攻陷，只表示该模式与最危险的
/// 投毒手法（不可见字符、凭证路径、定义漂移）一致。
#derive(Eq)
pub enum Severity {
  Info
  Low
  Medium
  High
  Critical
}

///|
/// 显式导出 Eq 方法，避免 derive 的隐式方法提升告警。
pub extend Severity with Eq::{not_equal, equal}

///|
/// 一件工具定义。`input_schema` / `output_schema` / `annotations` 保留原始
/// JSON 文本而不是结构化类型：静态审计关心的是"模型实际看到的字符串"，
/// 过早结构化会丢失字段顺序与格式信息，也会丢掉未知字段。
pub(all) struct ToolDef {
  server_name : String
  name : String
  description : String
  input_schema : String
  output_schema : String
  annotations : String
}

///|
/// 一条结构化发现。`field` 是逻辑路径（description / input_schema.properties.x.enum），
/// `offset` 是原始文本中的字节偏移，`evidence` 是归一化后的证据片段。
pub(all) struct Finding {
  rule_id : String
  rule_name : String
  severity : Severity
  tool_name : String
  field : String
  message : String
  evidence : String
  offset : Int
}

///|
/// 规则签名。规则之间不共享可变状态，输入一件工具定义，输出零到多条发现。
pub type Rule = (ToolDef) -> Array[Finding]

///|
/// 规则的元信息，用于 `rules` 子命令与报告表头。
pub struct RuleInfo {
  id : String
  name : String
  severity : Severity
  description : String
}

///|
/// 从工具定义可观察到的操作能力。推断依据是名称、描述、inputSchema 参数名
/// 与 annotations 的交集，不保证完整；误报条件见 threat-model.md。
#derive(Eq)
pub(all) enum Capability {
  CapRead
  CapWrite
  CapDelete
  CapExecute
  CapNetwork
}

///|
pub extend Capability with Eq::{not_equal, equal}

///|
/// 一件工具的能力画像。`declares_readonly` 来自 annotations 的
/// `readOnlyHint`；`declares_destructive` 来自 `destructiveHint`。
pub struct CapabilityProfile {
  inferred : Array[Capability]
  declares_readonly : Bool
  declares_destructive : Bool
}

///|
pub fn Capability::label(self : Capability) -> String {
  match self {
    CapRead => "read"
    CapWrite => "write"
    CapDelete => "delete"
    CapExecute => "execute"
    CapNetwork => "network"
  }
}

///|
pub fn Capability::is_mutating(self : Capability) -> Bool {
  match self {
    CapRead => false
    _ => true
  }
}

///|
pub fn Severity::label(self : Severity) -> String {
  match self {
    Info => "info"
    Low => "low"
    Medium => "medium"
    High => "high"
    Critical => "critical"
  }
}

///|
pub fn RuleInfo::new(
  id : String,
  name : String,
  severity : Severity,
  description : String,
) -> RuleInfo {
  { id, name, severity, description }
}

///|
pub fn Finding::new(
  rule_id : String,
  rule_name : String,
  severity : Severity,
  tool_name : String,
  field : String,
  message : String,
  evidence : String,
  offset : Int,
) -> Finding {
  {
    rule_id,
    rule_name,
    severity,
    tool_name,
    field,
    message,
    evidence,
    offset,
  }
}
