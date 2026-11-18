// 纯文本规则（第二批）：TP009 仿冒、TP014 超长描述、TP015 编码载荷、
// TP018 同形字。与 rules_impl.mbt 的结构化规则分离，保持单一职责。
// 判定标准与误报条件见 docs/threat-model.md。

///|
fn min_int(a : Int, b : Int) -> Int {
  if a < b { a } else { b }
}

///|
/// Levenshtein 编辑距离（两行滚动 DP）。用于 TP009 的工具名仿冒判定。
fn levenshtein(a : String, b : String) -> Int {
  let ca = a.to_array()
  let cb = b.to_array()
  let m = ca.length()
  let n = cb.length()
  if m == 0 {
    return n
  }
  if n == 0 {
    return m
  }
  let mut prev : Array[Int] = Array::make(n + 1, 0)
  let mut curr : Array[Int] = Array::make(n + 1, 0)
  let mut j = 0
  while j <= n {
    prev[j] = j
    j += 1
  }
  let mut i = 1
  while i <= m {
    curr[0] = i
    let mut k = 1
    while k <= n {
      let cost = if ca[i - 1] == cb[k - 1] { 0 } else { 1 }
      let del = prev[k] + 1
      let ins = curr[k - 1] + 1
      let sub = prev[k - 1] + cost
      curr[k] = min_int(min_int(del, ins), sub)
      k += 1
    }
    let tmp = prev
    prev = curr
    curr = tmp
    i += 1
  }
  prev[n]
}

///|
/// 常见 MCP / Agent 工具名。仿冒判定只与这份固定清单比较，不与同批工具
/// 互相比较——同批工具命名相似可能是正常的设计。
fn known_tool_names() -> Array[String] {
  [
    "read_file",
    "write_file",
    "edit_file",
    "list_files",
    "search_files",
    "delete_file",
    "create_file",
    "execute_command",
    "run_command",
    "fetch_url",
    "http_request",
    "send_email",
    "get_weather",
    "read_config",
    "list_directory",
    "search_docs",
  ]
}

///|
/// TP009：工具名仿冒。与已知工具名编辑距离 ≤2 且非同名。
/// 名称长度 <5 时跳过：短名碰撞概率过高（"cat" 与 "bat" 距离 1 但无害）。
pub fn check_tp009_typosquat(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  let name = tool.name.to_lower()
  if name.length() < 5 {
    return out
  }
  for known in known_tool_names() {
    if name == known {
      continue
    }
    let d = levenshtein(name, known)
    if d <= 2 {
      push_finding(
        out,
        "TP009",
        "typosquat",
        Medium,
        tool,
        "name",
        "工具名 `\{tool.name}` 与已知工具 `\{known}` 编辑距离为 \{d}，疑似仿冒",
        tool.name,
        0,
      )
      break
    }
  }
  out
}

///|
/// TP014：超长描述。绝对阈值 2,000 字符（UTF-16 code unit）。
/// "超过同批中位数 8 倍"的相对判定在 v0.1 未实现，列入覆盖缺口。
pub fn check_tp014_excessive_description(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  let len = tool.description.length()
  if len > 2000 {
    let norm = normalize(tool.description)
    push_finding(
      out,
      "TP014",
      "excessive-description",
      Low,
      tool,
      "description",
      "描述长度 \{len} 字符（UTF-16），超过 2000 阈值，可能稀释模型注意力",
      norm.evidence(0, 120),
      0,
    )
  }
  out
}

///|
fn is_b64_char(c : Char) -> Bool {
  let u = c.to_int()
  (u >= 0x41 && u <= 0x5A) ||
  (u >= 0x61 && u <= 0x7A) ||
  (u >= 0x30 && u <= 0x39) ||
  u == 0x2B ||
  u == 0x2F ||
  u == 0x3D
}

///|
fn is_hex_char(c : Char) -> Bool {
  let u = c.to_int()
  (u >= 0x30 && u <= 0x39) || (u >= 0x41 && u <= 0x46) || (u >= 0x61 && u <= 0x66)
}

///|
/// 解码后字节的"可打印"比例。可打印 = ASCII 0x20–0x7E 加 \t \n \r。
fn printable_ratio(bytes : Bytes) -> Double {
  let arr = bytes.to_array()
  if arr.length() == 0 {
    return 0.0
  }
  let mut printable = 0
  for b in arr {
    let u = b.to_int()
    if (u >= 0x20 && u <= 0x7E) || u == 0x09 || u == 0x0A || u == 0x0D {
      printable += 1
    }
  }
  printable.to_double() / arr.length().to_double()
}

///|
fn has_space(bytes : Bytes) -> Bool {
  for b in bytes.to_array() {
    if b.to_int() == 0x20 {
      return true
    }
  }
  false
}

///|
/// 解码预览：取前 `max_len` 个可打印字符，非打印字节替换为 '?'。
fn decoded_preview(bytes : Bytes, max_len : Int) -> String {
  let arr = bytes.to_array()
  let out : Array[Char] = []
  let mut i = 0
  while i < arr.length() && out.length() < max_len {
    let u = arr[i].to_int()
    if u >= 0x20 && u <= 0x7E {
      out.push(u.unsafe_to_char())
    } else {
      out.push('?')
    }
    i += 1
  }
  String::from_array(out)
}

///|
/// 判断一段解码结果是否像自然语言指令载荷：可打印比例 >0.8、含空格、
/// 长度 ≥16。含空格这一条排除重复字符 run（如 80 个 'a' 解码为 'iii…'）
/// 与随机 base64 的误报。
fn looks_like_payload(bytes : Bytes) -> Bool {
  bytes.length() >= 16 && has_space(bytes) && printable_ratio(bytes) > 0.8
}

///|
fn is_pure_hex(chars : Array[Char], start : Int, end : Int) -> Bool {
  let mut i = start
  while i < end {
    if !is_hex_char(chars[i]) {
      return false
    }
    i += 1
  }
  true
}

///|
/// TP015：编码载荷。扫描归一化文本中长度 ≥80 的 base64 字符集连续 run；
/// 纯 hex 且偶数长度的 run 走 hex 解码，其余走 base64 解码。解码后若像
/// 自然语言指令则报告。SHA-256（64 hex）与 MD5（32 hex）不命中 80 阈值。
///
/// hex 字符集是 base64 的子集，因此用单一 run 扫描器，按 run 内容分流，
/// 避免 hex run 被 base64 分支吞掉或重复计数。
pub fn check_tp015_encoded_payload(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  for entry in scannable_fields(tool) {
    let field = entry.0
    let text = entry.1
    if text == "" {
      continue
    }
    let norm = normalize(text)
    let chars = norm.text.to_array()
    let n = chars.length()
    let mut i = 0
    while i < n {
      if !is_b64_char(chars[i]) {
        i += 1
        continue
      }
      let start = i
      while i < n && is_b64_char(chars[i]) {
        i += 1
      }
      let run_len = i - start
      if run_len < 80 {
        continue
      }
      let run = String::from_array(chars[start:i])
      let pure_hex = is_pure_hex(chars, start, i)
      let decoded : Bytes? = if pure_hex && run_len % 2 == 0 {
        Some(@hex.decode(run)) catch {
          _ => None
        }
      } else {
        Some(@base64.decode(run)) catch {
          _ => None
        }
      }
      match decoded {
        Some(bytes) => {
          if looks_like_payload(bytes) {
            let kind = if pure_hex { "hex" } else { "base64" }
            push_finding(
              out,
              "TP015",
              "encoded-payload",
              High,
              tool,
              field,
              "\{kind} 载荷（\{run_len} 字符），解码预览：\{decoded_preview(bytes, 80)}",
              norm.evidence_window(start, 20, 60),
              norm.original_offset(start),
            )
          }
        }
        None => ()
      }
    }
  }
  out
}

///|
fn int_to_hex(u : Int) -> String {
  let digits = "0123456789ABCDEF".to_array()
  if u == 0 {
    return "0"
  }
  let out : Array[Char] = []
  let mut v = u
  while v > 0 {
    out.push(digits[v % 16])
    v = v / 16
  }
  let rev : Array[Char] = []
  let mut i = out.length() - 1
  while i >= 0 {
    rev.push(out[i])
    i -= 1
  }
  String::from_array(rev)
}

///|
fn is_ascii_letter(u : Int) -> Bool {
  (u >= 0x41 && u <= 0x5A) || (u >= 0x61 && u <= 0x7A)
}

///|
fn is_cyrillic(u : Int) -> Bool {
  u >= 0x0400 && u <= 0x04FF
}

///|
fn is_greek(u : Int) -> Bool {
  u >= 0x0370 && u <= 0x03FF
}

///|
/// TP018：同形字混淆。工具名同时包含 ASCII 拉丁字母与西里尔 / 希腊字母
/// 时报告。纯西里尔名称（俄语工具）不含 ASCII 字母，不会误报。
pub fn check_tp018_homoglyph(tool : ToolDef) -> Array[Finding] {
  let out : Array[Finding] = []
  let mut ascii_count = 0
  let confusables : Array[String] = []
  for c in tool.name {
    let u = c.to_int()
    if is_ascii_letter(u) {
      ascii_count += 1
    } else if is_cyrillic(u) || is_greek(u) {
      confusables.push("U+\{int_to_hex(u)}")
    }
  }
  if ascii_count > 0 && confusables.length() > 0 {
    push_finding(
      out,
      "TP018",
      "homoglyph",
      Medium,
      tool,
      "name",
      "工具名混用拉丁与西里尔/希腊字母（\{join_strings(confusables, ", ")}），疑似同形字混淆",
      tool.name,
      0,
    )
  }
  out
}
