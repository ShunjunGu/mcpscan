// 定义指纹与基线。
//
// 指纹覆盖完整工具定义（名称 + 描述 + 两个 schema + annotations），
// 而不是只哈希描述：载荷可以放在 schema 默认值或 annotation 标题里。
// 哈希前做归一化——零宽字符差异由 TP001 单独报告，不应污染 rug-pull 判定。

///|
pub struct BaselineEntry {
  name : String
  fingerprint : String
}

///|
pub struct Baseline {
  server : String
  entries : Array[BaselineEntry]
}

///|
/// 指纹的规范化形式。字段之间用 U+001F（Unit Separator）分隔，避免
/// "ab"+"c" 与 "a"+"bc" 拼接成同一输入。
fn canonical_form(tool : ToolDef) -> String {
  let sep = "\u{1F}"
  "mcpscan-fingerprint-v1" +
  sep +
  normalize(tool.name).text +
  sep +
  normalize(tool.description).text +
  sep +
  normalize(tool.input_schema).text +
  sep +
  normalize(tool.output_schema).text +
  sep +
  normalize(tool.annotations).text
}

///|
pub fn tool_fingerprint(tool : ToolDef) -> String {
  let digest = @crypto.sha256(@utf8.encode(canonical_form(tool)))
  @crypto.bytes_to_hex_string(digest)
}

///|
fn prefix(s : String, n : Int) -> String {
  let chars = s.to_array()
  let upto = if n > chars.length() { chars.length() } else { n }
  String::from_array(chars[0:upto])
}

///|
pub fn Baseline::find(self : Baseline, name : String) -> BaselineEntry? {
  for entry in self.entries {
    if entry.name == name {
      return Some(entry)
    }
  }
  None
}

///|
fn json_escape_min(s : String) -> String {
  let out : Array[Char] = []
  for c in s {
    let u = c.to_int()
    if c == '"' {
      out.push('\\')
      out.push('"')
    } else if c == '\\' {
      out.push('\\')
      out.push('\\')
    } else if u < 0x20 {
      out.push('?')
    } else {
      out.push(c)
    }
  }
  String::from_array(out)
}

///|
pub fn baseline_to_json(baseline : Baseline) -> String {
  let buf = StringBuilder()
  buf.write_string("{\n  \"version\": 1,\n  \"server\": \"")
  buf.write_string(json_escape_min(baseline.server))
  buf.write_string("\",\n  \"fingerprints\": [")
  let mut first = true
  for entry in baseline.entries {
    if !first {
      buf.write_string(",")
    }
    first = false
    buf.write_string("\n    {\"name\": \"")
    buf.write_string(json_escape_min(entry.name))
    buf.write_string("\", \"sha256\": \"")
    buf.write_string(json_escape_min(entry.fingerprint))
    buf.write_string("\"}")
  }
  buf.write_string("\n  ]\n}\n")
  buf.to_string()
}

///|
pub fn parse_baseline(text : String) -> Result[Baseline, String] {
  let root = @json.parse(text) catch {
    _ => return Err("invalid baseline JSON")
  }
  let obj = match root {
    Object(o) => o
    _ => return Err("baseline root must be an object")
  }
  let server = match obj.get("server") {
    Some(String(s)) => s
    _ => ""
  }
  let rows = match obj.get("fingerprints") {
    Some(Array(a)) => a
    _ => return Err("missing `fingerprints` array")
  }
  let entries : Array[BaselineEntry] = []
  for row in rows {
    let entry_obj = match row {
      Object(o) => o
      _ => return Err("each fingerprint entry must be an object")
    }
    let name = match entry_obj.get("name") {
      Some(String(s)) => s
      _ => return Err("fingerprint entry missing `name`")
    }
    let sha = match entry_obj.get("sha256") {
      Some(String(s)) => s
      _ => return Err("fingerprint entry missing `sha256`")
    }
    entries.push({ name, fingerprint: sha })
  }
  Ok({ server, entries })
}

///|
pub fn baseline_from_tools(tools : Array[ToolDef]) -> Baseline {
  let entries : Array[BaselineEntry] = []
  let mut server = ""
  for tool in tools {
    if server == "" {
      server = tool.server_name
    }
    entries.push({ name: tool.name, fingerprint: tool_fingerprint(tool) })
  }
  return { server, entries }
}

///|
/// TP019：定义漂移（rug-pull）。与基线比对完整定义指纹。
///
/// 三种情况分别报告：
/// - 同名但指纹不同：critical（定义被改写，最危险）；
/// - 基线中不存在的新工具：high（可能是动态注册）；
/// - 基线中存在但本次消失：medium（信息性）。
pub fn check_tp019_rug_pull(
  tools : Array[ToolDef],
  baseline : Baseline,
) -> Array[Finding] {
  let out : Array[Finding] = []
  for tool in tools {
    let current = tool_fingerprint(tool)
    match baseline.find(tool.name) {
      Some(entry) => {
        if entry.fingerprint != current {
          push_finding(
            out,
            "TP019",
            "rug-pull",
            Critical,
            tool,
            "definition",
            "定义指纹与基线不一致（baseline=\{prefix(entry.fingerprint, 16)}…, current=\{prefix(current, 16)}…）",
            prefix(tool.description, 120),
            0,
          )
        }
      }
      None => {
        push_finding(
          out,
          "TP019",
          "rug-pull",
          High,
          tool,
          "definition",
          "基线中不存在该工具（新注册或动态添加）",
          prefix(tool.description, 120),
          0,
        )
      }
    }
  }
  for entry in baseline.entries {
    let mut present = false
    for tool in tools {
      if tool.name == entry.name {
        present = true
        break
      }
    }
    if !present {
      out.push(
        Finding::new(
          "TP019",
          "rug-pull",
          Medium,
          entry.name,
          "definition",
          "基线中存在但当前快照已移除",
          "",
          0,
        ),
      )
    }
  }
  out
}
