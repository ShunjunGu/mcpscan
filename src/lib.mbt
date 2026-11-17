// 库入口：CLI 的薄封装。所有参数解析在 cmd/main，这里提供可被宿主直接
// 调用的 API（audit_tools / audit_snapshot）。

///|
pub fn version() -> String {
  "0.1.0"
}

///|
pub fn print_usage() -> Unit {
  println("mcpscan \{version()} — static audit for MCP tool definitions")
  println("")
  println("USAGE:")
  println("  mcpscan scan --snapshot <tools.json> [--format text|json|sarif|markdown]")
  println("  mcpscan scan --config <mcp.json>")
  println("  mcpscan baseline --snapshot <tools.json> --write <baseline.json>")
  println("  mcpscan rules")
  println("  mcpscan version")
  println("")
  println("EXIT CODES:")
  println("  0  no findings")
  println("  1  high or critical finding present")
  println("  2  usage error or read failure")
}

///|
pub fn print_rules() -> Unit {
  println("id    severity  name")
  for info in rule_infos() {
    println(
      "\{pad_right(info.id, 6)}\{pad_right(info.severity.label(), 10)}\{info.name}",
    )
  }
}

///|
fn pad_right(s : String, width : Int) -> String {
  let mut out = s
  while out.length() < width {
    out = out + " "
  }
  out
}

///|
fn count_severity(findings : Array[Finding], sev : Severity) -> Int {
  let mut n = 0
  for f in findings {
    if f.severity == sev {
      n += 1
    }
  }
  n
}

///|
fn render_text(snap : Snapshot, findings : Array[Finding]) -> Unit {
  let server = if snap.server == "" {
    "(unnamed)"
  } else {
    snap.server
  }
  println(
    "server: \{server}  tools: \{snap.tools.length()}  findings: \{findings.length()}",
  )
  if findings.length() > 0 {
    println(
      "  critical=\{count_severity(findings, Critical)} high=\{count_severity(findings, High)} medium=\{count_severity(findings, Medium)} low=\{count_severity(findings, Low)} info=\{count_severity(findings, Info)}",
    )
  }
  let mut index = 1
  for f in findings {
    println("")
    println(
      "\{index}. \{f.rule_id} \{f.rule_name} [\{f.severity.label()}] tool=\{f.tool_name} field=\{f.field} offset=\{f.offset}",
    )
    println("   \{f.message}")
    if f.evidence != "" {
      println("   evidence: \{f.evidence}")
    }
    index += 1
  }
}

///|
fn sarif_level(sev : Severity) -> String {
  match sev {
    Critical | High => "error"
    Medium => "warning"
    _ => "note"
  }
}

///|
/// 最小可用的 SARIF 2.1.0 输出：工具驱动信息 + 规则清单 + 结果。
/// 位置使用快照文件 URI 与 `startColumn`（工具定义内的偏移），因为静态
/// 审计拿不到原始文件行号；tool/field/offset 同时写入 properties 便于排查。
fn render_sarif(
  snap : Snapshot,
  findings : Array[Finding],
  source_path : String,
) -> Unit {
  let buf = StringBuilder()
  buf.write_string("{\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"version\": \"2.1.0\",\n  \"runs\": [\n    {\n      \"tool\": {\n        \"driver\": {\n          \"name\": \"mcpscan\",\n          \"version\": \"")
  buf.write_string(version())
  buf.write_string("\",\n          \"informationUri\": \"https://github.com/ShunjunGu/mcpscan\",\n          \"rules\": [")
  let infos = rule_infos()
  let mut first_rule = true
  for info in infos {
    if !first_rule {
      buf.write_string(",")
    }
    first_rule = false
    buf.write_string("\n            {\"id\": \"")
    buf.write_string(json_escape(info.id))
    buf.write_string("\", \"name\": \"")
    buf.write_string(json_escape(info.name))
    buf.write_string("\", \"shortDescription\": {\"text\": \"")
    buf.write_string(json_escape(info.description))
    buf.write_string("\"}, \"defaultConfiguration\": {\"level\": \"")
    buf.write_string(sarif_level(info.severity))
    buf.write_string("\"}}")
  }
  buf.write_string("\n          ]\n        }\n      },\n      \"results\": [")
  let mut first = true
  for f in findings {
    if !first {
      buf.write_string(",")
    }
    first = false
    buf.write_string("\n        {\n          \"ruleId\": \"")
    buf.write_string(json_escape(f.rule_id))
    buf.write_string("\",\n          \"level\": \"")
    buf.write_string(sarif_level(f.severity))
    buf.write_string("\",\n          \"message\": {\"text\": \"")
    buf.write_string(json_escape(f.message))
    buf.write_string("\"},\n          \"locations\": [{\"physicalLocation\": {\"artifactLocation\": {\"uri\": \"")
    buf.write_string(json_escape(source_path))
    buf.write_string("\"}, \"region\": {\"startLine\": 1, \"startColumn\": ")
    buf.write_string(f.offset.to_string())
    buf.write_string("}}}],\n          \"properties\": {\"tool\": \"")
    buf.write_string(json_escape(f.tool_name))
    buf.write_string("\", \"field\": \"")
    buf.write_string(json_escape(f.field))
    buf.write_string("\", \"offset\": ")
    buf.write_string(f.offset.to_string())
    buf.write_string(", \"evidence\": \"")
    buf.write_string(json_escape(f.evidence))
    buf.write_string("\"}\n        }")
  }
  buf.write_string("\n      ]\n    }\n  ]\n}\n")
  println(buf.to_string())
  let _ = snap
}

///|
fn render_report(
  snap : Snapshot,
  findings : Array[Finding],
  format : String,
  source_path : String,
) -> Unit {
  if format == "json" {
    render_json(snap, findings)
  } else if format == "markdown" {
    render_markdown(snap, findings)
  } else if format == "sarif" {
    render_sarif(snap, findings, source_path)
  } else {
    render_text(snap, findings)
  }
}

///|
fn json_escape(s : String) -> String {
  let out : Array[Char] = []
  for c in s {
    let u = c.to_int()
    if c == '"' {
      out.push('\\')
      out.push('"')
    } else if c == '\\' {
      out.push('\\')
      out.push('\\')
    } else if u == 0x0A {
      out.push('\\')
      out.push('n')
    } else if u == 0x0D {
      out.push('\\')
      out.push('r')
    } else if u == 0x09 {
      out.push('\\')
      out.push('t')
    } else if u < 0x20 {
      out.push('?')
    } else {
      out.push(c)
    }
  }
  String::from_array(out)
}

///|
fn render_json(snap : Snapshot, findings : Array[Finding]) -> Unit {
  let buf = StringBuilder()
  buf.write_string("{\"server\":\"")
  buf.write_string(json_escape(snap.server))
  buf.write_string("\",\"tool_count\":")
  buf.write_string(snap.tools.length().to_string())
  buf.write_string(",\"findings\":[")
  let mut first = true
  for f in findings {
    if !first {
      buf.write_string(",")
    }
    first = false
    buf.write_string("{\"rule_id\":\"")
    buf.write_string(json_escape(f.rule_id))
    buf.write_string("\",\"rule_name\":\"")
    buf.write_string(json_escape(f.rule_name))
    buf.write_string("\",\"severity\":\"")
    buf.write_string(f.severity.label())
    buf.write_string("\",\"tool\":\"")
    buf.write_string(json_escape(f.tool_name))
    buf.write_string("\",\"field\":\"")
    buf.write_string(json_escape(f.field))
    buf.write_string("\",\"offset\":")
    buf.write_string(f.offset.to_string())
    buf.write_string(",\"message\":\"")
    buf.write_string(json_escape(f.message))
    buf.write_string("\",\"evidence\":\"")
    buf.write_string(json_escape(f.evidence))
    buf.write_string("\"}")
  }
  buf.write_string("]}")
  println(buf.to_string())
}

///|
fn render_markdown(snap : Snapshot, findings : Array[Finding]) -> Unit {
  println("# mcpscan report: \{snap.server}")
  println("")
  println("| rule | severity | tool | field | evidence |")
  println("| --- | --- | --- | --- | --- |")
  for f in findings {
    println(
      "| \{f.rule_id} \{f.rule_name} | \{f.severity.label()} | \{f.tool_name} | \{f.field} | \{f.evidence} |",
    )
  }
}

///|
pub fn run_scan(args : ArrayView[String]) -> Unit {
  let mut snapshot_path = ""
  let mut format = "text"
  let mut baseline_path = ""
  let mut i = 0
  while i < args.length() {
    let a = args[i]
    if a == "--snapshot" && i + 1 < args.length() {
      snapshot_path = args[i + 1]
      i += 2
    } else if a == "--format" && i + 1 < args.length() {
      format = args[i + 1]
      i += 2
    } else if a == "--baseline" && i + 1 < args.length() {
      baseline_path = args[i + 1]
      i += 2
    } else {
      i += 1
    }
  }
  if snapshot_path == "" {
    println("scan: --snapshot <path> is required")
    print_usage()
    exit_error()
    return
  }
  let text = @fs.read_file_to_string(snapshot_path) catch {
    _ => {
      println("scan: cannot read \{snapshot_path}")
      exit_error()
      return
    }
  }
  let snap = match parse_snapshot(text) {
    Ok(s) => s
    Err(e) => {
      println("scan: \{e}")
      exit_error()
      return
    }
  }
  let baseline : Baseline? = if baseline_path == "" {
    None
  } else {
    let btext = @fs.read_file_to_string(baseline_path) catch {
      _ => {
        println("scan: cannot read baseline \{baseline_path}")
        exit_error()
        return
      }
    }
    match parse_baseline(btext) {
      Ok(b) => Some(b)
      Err(e) => {
        println("scan: baseline \{e}")
        exit_error()
        return
      }
    }
  }
  let findings = audit_tools_with(snap.tools, baseline)
  render_report(snap, findings, format, snapshot_path)
  if has_blocking(findings) {
    exit_blocked()
  } else {
    exit_ok()
  }
}

///|
/// 生成基线：读取快照，对每件工具计算定义指纹并写出。
pub fn run_baseline(args : ArrayView[String]) -> Unit {
  let mut snapshot_path = ""
  let mut write_path = ""
  let mut i = 0
  while i < args.length() {
    let a = args[i]
    if a == "--snapshot" && i + 1 < args.length() {
      snapshot_path = args[i + 1]
      i += 2
    } else if a == "--write" && i + 1 < args.length() {
      write_path = args[i + 1]
      i += 2
    } else {
      i += 1
    }
  }
  if snapshot_path == "" || write_path == "" {
    println("baseline: --snapshot <path> and --write <path> are required")
    exit_error()
    return
  }
  let text = @fs.read_file_to_string(snapshot_path) catch {
    _ => {
      println("baseline: cannot read \{snapshot_path}")
      exit_error()
      return
    }
  }
  let snap = match parse_snapshot(text) {
    Ok(s) => s
    Err(e) => {
      println("baseline: \{e}")
      exit_error()
      return
    }
  }
  let baseline = baseline_from_tools(snap.tools)
  let json = baseline_to_json(baseline)
  @fs.write_string_to_file(write_path, json) catch {
    _ => {
      println("baseline: cannot write \{write_path}")
      exit_error()
      return
    }
  }
  println("baseline: wrote \{snap.tools.length()} fingerprints to \{write_path}")
  exit_ok()
}
