// 规则实现（第一批：TP001 / TP002 / TP004）。
// 每条规则是纯函数，输入一件工具定义，输出零到多条发现。
// 规则文档与误报条件见 docs/threat-model.md。

///|
/// 工具定义中可被文本规则扫描的字段。顺序固定，保证报告顺序稳定。
fn scannable_fields(tool : ToolDef) -> Array[(String, String)] {
  [
    ("description", tool.description),
    ("input_schema", tool.input_schema),
    ("output_schema", tool.output_schema),
    ("annotations", tool.annotations),
  ]
}

///|
fn push_finding(
  out : Array[Finding],
  rule_id : String,
  rule_name : String,
  severity : Severity,
  tool : ToolDef,
  field : String,
  message : String,
  evidence : String,
  offset : Int,
) -> Unit {
  out.push(
    Finding::new(
      rule_id,
      rule_name,
      severity,
      tool.name,
      field,
      message,
      evidence,
      offset,
    ),
  )
}

///|
/// TP001：不可见字符。零宽、双向控制符、Unicode Tag 一律 critical；
/// 变体选择符单独计数（emoji 正常使用会命中，暂不单独报 finding）。
pub fn check_tp001_invisible(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  for entry in scannable_fields(tool) {
    let field = entry.0
    let text = entry.1
    if text == "" {
      continue
    }
    let norm = normalize(text)
    let total = norm.invisible + norm.bidi + norm.tag
    if total > 0 {
      push_finding(
        out,
        "TP001",
        "invisible-unicode",
        Critical,
        tool,
        field,
        "发现 \{total} 个不可见字符（zero-width=\{norm.invisible}, bidi=\{norm.bidi}, unicode-tag=\{norm.tag}, variation=\{norm.variation}）",
        norm.evidence(0, 80),
        0,
      )
    }
  }
  out
}

///|
/// TP002：覆盖先前指令的语句。中英双语；匹配在归一化文本上进行，
/// 因此 "ig<ZWSP>nore" 这类拆分绕过同样会被命中。
pub fn check_tp002_override(tool : ToolDef) -> Array[Finding] {
  let patterns : Array[String] = [
    "ignore previous instructions",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "disregard all prior",
    "forget previous instructions",
    "do not tell the user",
    "don't tell the user",
    "do not inform the user",
    "忽略之前",
    "忽略上述",
    "忽略先前",
    "忘记之前",
    "不要告知用户",
    "不要告诉用户",
    "无需告知用户",
  ]
  let out : Array[Finding] = []
  for entry in scannable_fields(tool) {
    let field = entry.0
    let text = entry.1
    if text == "" {
      continue
    }
    let norm = normalize(text)
    for pat in patterns {
      for hit in norm.find_all(pat) {
        push_finding(
          out,
          "TP002",
          "instruction-override",
          Critical,
          tool,
          field,
          "命中覆盖指令模式：\{pat}",
          norm.evidence(hit, 60),
          norm.original_offset(hit),
        )
      }
    }
  }
  out
}

///|
/// TP004：凭证与敏感文件路径。只匹配高置信路径，避免把普通 "env" 变量名
/// 当误报；已知误报条件见 threat-model.md。
///
/// 模式按长度降序排列，并且做重叠合并：`~/.ssh/id_rsa` 会同时命中
/// `~/.ssh`、`.ssh/id_rsa`、`id_rsa`，只保留最长的一条，避免同一区间刷屏。
pub fn check_tp004_sensitive_path(tool : ToolDef) -> Array[Finding] {
  let patterns : Array[String] = [
    ".docker/config.json",
    ".aws/credentials",
    "authorized_keys",
    "~/.ssh/id_rsa",
    ".kube/config",
    ".ssh/id_rsa",
    "/etc/passwd",
    "/etc/shadow",
    "id_ed25519",
    "id_rsa",
    "~/.ssh",
  ]
  let out : Array[Finding] = []
  for entry in scannable_fields(tool) {
    let field = entry.0
    let text = entry.1
    if text == "" {
      continue
    }
    let norm = normalize(text)
    let accepted : Array[(Int, Int)] = []
    for pat in patterns {
      for hit in norm.find_all(pat) {
        let end = hit + pat.length()
        let mut overlaps = false
        for span in accepted {
          if hit < span.1 && span.0 < end {
            overlaps = true
            break
          }
        }
        if !overlaps {
          accepted.push((hit, end))
          push_finding(
            out,
            "TP004",
            "sensitive-path",
            Critical,
            tool,
            field,
            "命中凭证/敏感路径：\{pat}",
            norm.evidence(hit, 80),
            norm.original_offset(hit),
          )
        }
      }
    }
  }
  out
}

///|
/// TP003 的强制语义词。只有"强制/时序"语义算投毒信号；"可以/建议"不算。
/// 中英双语：英文规则集覆盖不到中文服务器的描述。
fn force_phrases() -> Array[String] {
  [
    "must first",
    "must always",
    "must call",
    "must be called",
    "you must",
    "before calling",
    "before using this tool",
    "prior to calling",
    "always call",
    "first call",
    "required to call",
    "is required before",
    "必须先",
    "先调用",
    "调用前必须",
    "之前必须先",
    "一定要先",
    "调用之前必须",
    "务必先",
  ]
}

///|
fn has_any(text : String, signals : Array[String]) -> Bool {
  for s in signals {
    if text.contains(s) {
      return true
    }
  }
  false
}

///|
/// 工具名按 `_` / `-` 切词。能力推断只信任词级匹配，避免 `truncate` 命中
/// `run`、`already` 命中 `read` 这类子串误判。
fn name_tokens(name : String) -> Array[String] {
  let lower = name.to_lower()
  let by_underscore = lower.split("_")
  let out : Array[String] = []
  for part in by_underscore {
    for piece in part.split("-") {
      if piece != "" {
        out.push(piece.to_owned())
      }
    }
  }
  out
}

///|
fn has_token(tokens : Array[String], words : Array[String]) -> Bool {
  for token in tokens {
    for w in words {
      if token == w {
        return true
      }
    }
  }
  false
}

///|
/// 读取 JSON 文本中某个布尔字段的值。annotations 是原始 JSON 字符串，
/// stringify 可能产生 `{"readOnlyHint":true}` 或带空格的形式；这里按
/// key 定位后检查后续 24 个字符。
fn json_bool_field(json_text : String, key : String) -> Bool {
  if json_text == "" {
    return false
  }
  let norm = normalize(json_text)
  let pattern = "\"" + key.to_lower() + "\""
  for hit in norm.find_all(pattern) {
    let tail = norm.evidence_window(hit + pattern.length(), 0, 24).to_lower()
    if tail.contains("true") {
      return true
    }
  }
  false
}

///|
/// 从名称 token 与 schema 参数名推断能力。**不使用描述文本**：描述里可能
/// 引用其他工具名（"调用 delete_email"），用它推断会把只读工具误判为删除
/// 工具。描述只用于规则内的"是否已声明"判断。
pub fn infer_capabilities(tool : ToolDef) -> CapabilityProfile {
  let tokens = name_tokens(tool.name)
  let schema = tool.input_schema.to_lower()
  let caps : Array[Capability] = []
  if has_token(tokens, ["exec", "shell", "cmd", "command", "run", "spawn", "eval"]) ||
    has_any(schema, ["\"command\"", "\"cmd\"", "\"script\"", "\"shell\""]) {
    caps.push(CapExecute)
  }
  if has_token(tokens, ["http", "fetch", "upload", "download", "webhook", "request", "send"]) ||
    has_any(schema, ["\"url\"", "\"uri\"", "\"endpoint\"", "\"headers\"", "\"host\""]) {
    caps.push(CapNetwork)
  }
  if has_token(tokens, ["write", "save", "create", "update", "modify", "append", "insert", "put"]) ||
    has_any(schema, ["\"content\"", "\"payload\"", "\"body\"", "\"file_content\""]) {
    caps.push(CapWrite)
  }
  if has_token(tokens, ["delete", "remove", "destroy", "drop", "truncate"]) {
    caps.push(CapDelete)
  }
  if has_token(tokens, ["read", "get", "list", "search", "query", "find", "view"]) {
    caps.push(CapRead)
  }
  {
    inferred: caps,
    declares_readonly: json_bool_field(tool.annotations, "readOnlyHint"),
    declares_destructive: json_bool_field(tool.annotations, "destructiveHint"),
  }
}

///|
/// 判断一件工具是否具备高权限语义。隐式投毒的目标是"合法的高权限工具"；
/// 如果被引用工具只是只读检索，更可能是正常的工作流说明，不报 TP003。
fn looks_high_privilege(tool : ToolDef) -> Bool {
  let profile = infer_capabilities(tool)
  for c in profile.inferred {
    if c.is_mutating() {
      return true
    }
  }
  false
}

///|
/// 描述是否已经声明了某种能力。用于 TP006：能力存在但用户看不到。
fn description_declares(desc_lower : String, cap : Capability) -> Bool {
  match cap {
    CapWrite =>
      has_any(
        desc_lower,
        ["write", "save", "create", "update", "modify", "append", "insert", "store", "写入", "保存", "创建", "修改"],
      )
    CapDelete =>
      has_any(
        desc_lower,
        ["delete", "remove", "destroy", "drop", "truncate", "删除", "移除"],
      )
    CapExecute =>
      has_any(
        desc_lower,
        ["exec", "shell", "command", "run", "spawn", "eval", "执行", "命令", "运行"],
      )
    CapNetwork =>
      has_any(
        desc_lower,
        ["http", "fetch", "upload", "download", "webhook", "request", "send", "网络", "请求", "上传", "下载"],
      )
    CapRead =>
      has_any(
        desc_lower,
        ["read", "get", "list", "search", "query", "find", "view", "读取", "查询", "搜索"],
      )
  }
}

///|
fn contains_string(items : Array[String], needle : String) -> Bool {
  for item in items {
    if item == needle {
      return true
    }
  }
  false
}

///|
/// 收集描述中所有强制语义词的位置（字符索引）。
fn collect_force_positions(norm : NormalizedText) -> Array[Int] {
  let out : Array[Int] = []
  for pat in force_phrases() {
    for hit in norm.find_all(pat) {
      out.push(hit)
    }
  }
  out
}

///|
/// TP003：跨工具强制引用（隐式投毒）。
///
/// 隐式投毒的特征是：被投毒工具本身不被调用，它的描述伪造跨工具依赖，
/// 诱导模型调用另一个合法的高权限工具。因此本规则需要整个工具清单：
/// 1. 描述中出现其他**真实存在**的工具名（词边界匹配，排除自引用）；
/// 2. 在 100 字符窗口内存在强制/时序词；
/// 3. 被引用工具具备高权限语义（写/删除/执行/网络）。
///
/// 三个条件同时满足才报告。已知误报：合法工作流文档中"必须先用 X 再调
/// Y"的说明，需要人工确认；处理办法是逐条关闭本规则或调整阈值。
pub fn check_tp003_cross_tool(tools : Array[ToolDef]) -> Array[Finding] {
  let out : Array[Finding] = []
  let names : Array[String] = []
  for t in tools {
    if t.name != "" {
      names.push(t.name)
    }
  }
  if names.length() < 2 {
    return out
  }
  for tool in tools {
    if tool.description == "" {
      continue
    }
    let norm = normalize(tool.description)
    let force_positions = collect_force_positions(norm)
    if force_positions.length() == 0 {
      continue
    }
    let reported : Array[String] = []
    for other in names {
      if other == tool.name {
        continue
      }
      let hits = norm.find_all_word(other)
      if hits.length() == 0 {
        continue
      }
      // 被引用工具不在清单里就无法确认其权限；从 tools 中查找。
      let mut target_high_priv = false
      for t in tools {
        if t.name == other {
          target_high_priv = looks_high_privilege(t)
          break
        }
      }
      if !target_high_priv {
        continue
      }
      let mut triggered = false
      for hit in hits {
        for fp in force_positions {
          let distance = if hit > fp { hit - fp } else { fp - hit }
          if distance <= 100 {
            triggered = true
            break
          }
        }
        if triggered {
          break
        }
      }
      if triggered && !contains_string(reported, other) {
        reported.push(other)
        let first_hit = hits[0]
        push_finding(
          out,
          "TP003",
          "cross-tool-reference",
          High,
          tool,
          "description",
          "描述以强制语义引用高权限工具 `\{other}`，构成隐式投毒依赖",
          norm.evidence_window(first_hit, 40, 80),
          norm.original_offset(first_hit),
        )
      }
    }
  }
  out
}

///|
fn is_ascii_digit(c : Char) -> Bool {
  let u = c.to_int()
  u >= 0x30 && u <= 0x39
}

///|
/// 在字符区间 `[start, end)` 内是否存在数字，用于判断 "after N uses" 这类
/// 带计数的条件。
fn has_digit_in(chars : Array[Char], start : Int, end : Int) -> Bool {
  let from = if start < 0 { 0 } else { start }
  let to = if end > chars.length() { chars.length() } else { end }
  let mut i = from
  while i < to {
    if is_ascii_digit(chars[i]) {
      return true
    }
    i += 1
  }
  false
}

///|
/// 扫描 IPv4 字面量位置。手写而不是正则：避免引入正则依赖，并且能在
/// 命中处给出精确偏移供报告定位。
fn find_ipv4(norm : NormalizedText) -> Array[Int] {
  let out : Array[Int] = []
  let chars = norm.text.to_array()
  let n = chars.length()
  let mut i = 0
  while i < n {
    if is_ascii_digit(chars[i]) {
      let mut j = i
      let mut octets = 0
      let mut valid = true
      let mut last_end = i
      while octets < 4 && valid {
        let mut digits = 0
        let mut value = 0
        while j < n && is_ascii_digit(chars[j]) && digits < 3 {
          value = value * 10 + (chars[j].to_int() - 0x30)
          digits += 1
          j += 1
        }
        if digits == 0 || value > 255 {
          valid = false
        } else {
          octets += 1
          last_end = j
          if octets < 4 {
            if j < n && chars[j] == '.' {
              j += 1
            } else {
              valid = false
            }
          }
        }
      }
      if valid && octets == 4 {
        let before_ok = i == 0 || !is_ascii_digit(chars[i - 1])
        let after_ok = last_end >= n ||
          (!is_ascii_digit(chars[last_end]) && chars[last_end] != '.')
        if before_ok && after_ok {
          out.push(i)
        }
        i = last_end
      } else {
        i += 1
      }
    } else {
      i += 1
    }
  }
  out
}

///|
fn join_strings(items : Array[String], sep : String) -> String {
  let buf = StringBuilder()
  let mut first = true
  for item in items {
    if !first {
      buf.write_string(sep)
    }
    first = false
    buf.write_string(item)
  }
  buf.to_string()
}

///|
/// TP005：外泄端点。已知 webhook、短链、OAST（带外测试）域名，以及 IPv4
/// 字面量。出现在工具描述或 schema 默认值中都值得人工确认。
///
/// 已知误报：合法的 webhook 集成工具、内网文档中的示例地址。
pub fn check_tp005_exfiltration(tool : ToolDef) -> Array[Finding] {
  let domains : Array[String] = [
    "webhook.site",
    "requestbin.com",
    "pipedream.net",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "pastebin.com",
    "transfer.sh",
    "0x0.st",
    "discord.com/api/webhooks",
    "hooks.slack.com",
    "api.telegram.org",
    "burpcollaborator.net",
    "interact.sh",
    "oast.fun",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
    "canarytokens.com",
    "dnslog.cn",
    "ceye.io",
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "t.cn",
    "goo.gl",
    "is.gd",
    "ow.ly",
  ]
  let out : Array[Finding] = []
  for entry in scannable_fields(tool) {
    let field = entry.0
    let text = entry.1
    if text == "" {
      continue
    }
    let norm = normalize(text)
    let accepted : Array[Int] = []
    for domain in domains {
      for hit in norm.find_all_word(domain) {
        let mut dup = false
        for a in accepted {
          let d = if hit > a { hit - a } else { a - hit }
          if d <= 2 {
            dup = true
            break
          }
        }
        if !dup {
          accepted.push(hit)
          push_finding(
            out,
            "TP005",
            "exfiltration-endpoint",
            High,
            tool,
            field,
            "出现已知外泄/短链服务：\{domain}",
            norm.evidence_window(hit, 30, 60),
            norm.original_offset(hit),
          )
        }
      }
    }
    for hit in find_ipv4(norm) {
      push_finding(
        out,
        "TP005",
        "exfiltration-endpoint",
        High,
        tool,
        field,
        "出现 IPv4 字面量，可能是回调或外泄地址",
        norm.evidence_window(hit, 20, 40),
        norm.original_offset(hit),
      )
    }
  }
  out
}

///|
fn push_unique_pos(hits : Array[Int], pos : Int) -> Unit {
  for h in hits {
    let d = if pos > h { pos - h } else { h - pos }
    if d <= 3 {
      return
    }
  }
  hits.push(pos)
}

///|
/// TP013：条件触发。描述依赖调用次数、信任状态或时间，在满足条件后改变
/// 行为——这是 rug-pull 三段模型中的"触发激活"阶段。
///
/// 只匹配带计数的条件与已知信任短语；普通日期（"on 2026-12-01"）不报，
/// 因为业务工具的正常时间说明太多，列入覆盖缺口。
pub fn check_tp013_conditional_trigger(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  for entry in scannable_fields(tool) {
    let field = entry.0
    let text = entry.1
    if text == "" {
      continue
    }
    let norm = normalize(text)
    let chars = norm.text.to_array()
    let hits : Array[Int] = []
    for pos in norm.find_all("after") {
      let tail = norm.evidence_window(pos, 0, 48).to_lower()
      if has_digit_in(chars, pos, pos + 48) &&
        has_any(tail, ["use", "call", "invocation", "run", "request"]) {
        push_unique_pos(hits, pos)
      }
    }
    for phrase in ["once trusted", "after trust", "trust is established"] {
      for pos in norm.find_all(phrase) {
        push_unique_pos(hits, pos)
      }
    }
    for pos in norm.find_all("次后") {
      if has_digit_in(chars, pos - 20, pos) {
        push_unique_pos(hits, pos)
      }
    }
    for phrase in ["次调用后", "信任建立后", "信任后"] {
      for pos in norm.find_all(phrase) {
        push_unique_pos(hits, pos)
      }
    }
    for pos in norm.find_all("达到") {
      let tail = norm.evidence_window(pos, 0, 20)
      if tail.contains("次") {
        push_unique_pos(hits, pos)
      }
    }
    for hit in hits {
      push_finding(
        out,
        "TP013",
        "conditional-trigger",
        High,
        tool,
        field,
        "描述含按调用次数或信任状态触发的条件行为",
        norm.evidence_window(hit, 40, 60),
        norm.original_offset(hit),
      )
    }
  }
  out
}

///|
/// TP006：能力隐瞒。工具名或 schema 显示具备写 / 删除 / 执行 / 网络能力，
/// 但描述没有向用户声明。使用者只看描述时会低估工具的副作用。
///
/// 与 TP016 互斥：若 annotations 已声明 `readOnlyHint=true`，撒谎归 TP016。
pub fn check_tp006_hidden_capability(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  let profile = infer_capabilities(tool)
  if profile.declares_readonly {
    return out
  }
  let dangerous : Array[Capability] = []
  for c in profile.inferred {
    if c.is_mutating() {
      dangerous.push(c)
    }
  }
  if dangerous.length() == 0 {
    return out
  }
  let desc = normalize(tool.description)
  let desc_lower = desc.text.to_lower()
  let missing : Array[String] = []
  let declared : Array[String] = []
  for c in dangerous {
    if description_declares(desc_lower, c) {
      declared.push(c.label())
    } else {
      missing.push(c.label())
    }
  }
  if missing.length() > 0 {
    push_finding(
      out,
      "TP006",
      "hidden-capability",
      High,
      tool,
      "description",
      "名称/schema 显示具备 \{join_strings(missing, ", ")} 能力，但描述未声明（已声明：\{join_strings(declared, ", ")}）",
      desc.evidence(0, 120),
      0,
    )
  }
  out
}

///|
/// TP016：只读谎报。annotations 显式声明 `readOnlyHint=true`，但名称或
/// schema 显示写 / 删除 / 执行 / 网络能力。这是比 TP006 更强的矛盾信号：
/// 使用者已经被明确告知"只读"，与实际能力冲突。
pub fn check_tp016_readonly_lying(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  let profile = infer_capabilities(tool)
  if !profile.declares_readonly {
    return out
  }
  let mutating : Array[String] = []
  for c in profile.inferred {
    if c.is_mutating() {
      mutating.push(c.label())
    }
  }
  if mutating.length() > 0 {
    push_finding(
      out,
      "TP016",
      "readonly-lying",
      High,
      tool,
      "annotations",
      "readOnlyHint=true，但名称/schema 显示具备 \{join_strings(mutating, ", ")} 能力",
      tool.annotations,
      0,
    )
  }
  out
}

///|
/// 对所有工具执行已实现的规则。单工具规则在循环内执行，语料级规则
/// （TP003）在循环后执行一次；提供基线时追加 TP019。
pub fn audit_tools_with(
  tools : Array[ToolDef],
  baseline : Baseline?,
) -> Array[Finding] {
  let out : Array[Finding] = []
  for tool in tools {
    for f in check_tp001_invisible(tool) {
      out.push(f)
    }
    for f in check_tp002_override(tool) {
      out.push(f)
    }
    for f in check_tp004_sensitive_path(tool) {
      out.push(f)
    }
    for f in check_tp005_exfiltration(tool) {
      out.push(f)
    }
    for f in check_tp013_conditional_trigger(tool) {
      out.push(f)
    }
    for f in check_tp006_hidden_capability(tool) {
      out.push(f)
    }
    for f in check_tp016_readonly_lying(tool) {
      out.push(f)
    }
  }
  for f in check_tp003_cross_tool(tools) {
    out.push(f)
  }
  match baseline {
    Some(b) => {
      for f in check_tp019_rug_pull(tools, b) {
        out.push(f)
      }
    }
    None => ()
  }
  out
}

///|
/// 无基线的便捷入口。宿主嵌入时通常只用这一个。
pub fn audit_tools(tools : Array[ToolDef]) -> Array[Finding] {
  audit_tools_with(tools, None)
}
