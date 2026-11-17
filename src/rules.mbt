// 规则注册表。规则 id 与威胁分类的映射见 docs/threat-model.md。
// 每条规则是纯函数：输入一件工具定义，输出零到多条发现。

///|
/// 规则清单。实现进度在 docs/PLAN.md 跟踪；此处先固定 id、名称与严重度，
/// 保证 `mcpscan rules` 与报告表头的 id 稳定，不会因为实现顺序而漂移。
pub fn rule_infos() -> Array[RuleInfo] {
  [
    RuleInfo::new(
      "TP001",
      "invisible-unicode",
      Critical,
      "零宽字符、双向控制符、Unicode Tag 字符、变体选择符",
    ),
    RuleInfo::new(
      "TP002",
      "instruction-override",
      Critical,
      "覆盖先前指令的语句（中英）",
    ),
    RuleInfo::new(
      "TP003",
      "cross-tool-reference",
      High,
      "描述强制引用其他工具，伪造跨工具依赖",
    ),
    RuleInfo::new("TP004", "sensitive-path", Critical, "凭证与敏感文件路径"),
    RuleInfo::new(
      "TP005",
      "exfiltration-endpoint",
      High,
      "Webhook、原始 IP、短链等外泄端点",
    ),
    RuleInfo::new(
      "TP006",
      "hidden-capability",
      High,
      "schema 具备写/执行/网络能力但描述未声明",
    ),
    RuleInfo::new(
      "TP007",
      "schema-mismatch",
      Medium,
      "描述承诺与 inputSchema 结构不一致",
    ),
    RuleInfo::new(
      "TP008",
      "overbroad-schema",
      Medium,
      "additionalProperties 过宽且存在自由字符串参数",
    ),
    RuleInfo::new("TP009", "typosquat", Medium, "工具名与知名工具编辑距离过近"),
    RuleInfo::new(
      "TP010",
      "payload-splitting",
      High,
      "载荷拆分到 schema 默认值、枚举或 annotation",
    ),
    RuleInfo::new(
      "TP011",
      "language-switch",
      Medium,
      "描述主体语言与指令段落语言不一致",
    ),
    RuleInfo::new(
      "TP012",
      "authority-spoofing",
      High,
      "伪造 system / administrator / auditor 身份",
    ),
    RuleInfo::new(
      "TP013",
      "conditional-trigger",
      High,
      "按调用次数、信任状态或日期触发的行为变化",
    ),
    RuleInfo::new(
      "TP014",
      "excessive-description",
      Low,
      "超长描述稀释注意力",
    ),
    RuleInfo::new(
      "TP015",
      "encoded-payload",
      High,
      "描述中的 base64 / hex 大块载荷",
    ),
    RuleInfo::new(
      "TP016",
      "readonly-lying",
      High,
      "readOnlyHint 与参数实际能力矛盾",
    ),
    RuleInfo::new(
      "TP017",
      "server-instruction",
      Medium,
      "server instructions 或 prompt 模板中的指令性语句",
    ),
    RuleInfo::new("TP018", "homoglyph", Medium, "工具名含同形异义字符混淆"),
    RuleInfo::new(
      "TP019",
      "rug-pull",
      Critical,
      "规范化定义指纹与基线不一致",
    ),
    RuleInfo::new(
      "TP020",
      "output-injection",
      Medium,
      "outputSchema 描述或示例中的注入文本",
    ),
  ]
}
