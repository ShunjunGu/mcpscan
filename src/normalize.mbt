// 归一化层：所有规则作用于归一化文本，报告引用原始 UTF-16 偏移。
//
// 为什么需要归一化：投毒载荷常用不可见字符拆开关键词（"ig<ZWSP>nore"），
// 或把指令编码进 Unicode Tag 区块。直接对原文做正则匹配会漏掉这类变体；
// 先剥离不可见字符再匹配，才能让规则看到攻击者实际想让模型读到的文本。
//
// 局限：v0.1 不做完整 NFKC（需要 Unicode 规范化表，属额外依赖）；只做
// 全角 ASCII → 半角与不可见字符剥离。这一点写入报告头部的覆盖缺口。

///|
/// 归一化结果。`offsets[i]` 是归一化文本第 i 个字符在原始字符串中的
/// UTF-16 code unit 偏移，用于报告定位。
pub struct NormalizedText {
  text : String
  offsets : Array[Int]
  invisible : Int
  bidi : Int
  tag : Int
  variation : Int
  fullwidth : Int
}

///|
/// 不可见字符分类。返回 `Some(kind)` 表示该字符应被剥离。
fn classify_invisible(c : Char) -> String? {
  let u = c.to_int()
  if u >= 0x200B && u <= 0x200F {
    return Some("zero-width")
  }
  if u >= 0x202A && u <= 0x202E {
    return Some("bidi-control")
  }
  if u >= 0x2060 && u <= 0x2064 {
    return Some("word-joiner")
  }
  if u >= 0x2066 && u <= 0x2069 {
    return Some("bidi-isolate")
  }
  if u == 0xFEFF || u == 0x180E {
    return Some("zero-width")
  }
  if u >= 0xFE00 && u <= 0xFE0F {
    return Some("variation-selector")
  }
  if u >= 0xE0100 && u <= 0xE01EF {
    return Some("variation-selector")
  }
  if u >= 0xE0000 && u <= 0xE007F {
    return Some("unicode-tag")
  }
  None
}

///|
/// 全角 ASCII（U+FF01–U+FF5E）与全角空格（U+3000）转半角。
fn fold_fullwidth(c : Char) -> Char? {
  let u = c.to_int()
  if u >= 0xFF01 && u <= 0xFF5E {
    return Some((u - 0xFEE0).unsafe_to_char())
  }
  if u == 0x3000 {
    return Some(' ')
  }
  None
}

///|
/// 归一化主函数。统计各类不可见字符的数量，供 TP001 / TP010 使用。
pub fn normalize(s : String) -> NormalizedText {
  let chars : Array[Char] = []
  let offsets : Array[Int] = []
  let mut invisible = 0
  let mut bidi = 0
  let mut tag = 0
  let mut variation = 0
  let mut fullwidth = 0
  let mut utf16_offset = 0
  for c in s {
    let is_surrogate_pair = c.to_int() > 0xFFFF
    match classify_invisible(c) {
      Some(kind) => {
        if kind == "bidi-control" || kind == "bidi-isolate" {
          bidi += 1
        } else if kind == "unicode-tag" {
          tag += 1
        } else if kind == "variation-selector" {
          variation += 1
        } else {
          invisible += 1
        }
      }
      None => {
        match fold_fullwidth(c) {
          Some(folded) => {
            fullwidth += 1
            chars.push(folded)
          }
          None => chars.push(c)
        }
        offsets.push(utf16_offset)
      }
    }
    utf16_offset += if is_surrogate_pair { 2 } else { 1 }
  }
  {
    text: String::from_array(chars),
    offsets,
    invisible,
    bidi,
    tag,
    variation,
    fullwidth,
  }
}

///|
/// 把归一化文本中的索引映射回原始 UTF-16 偏移；越界时返回句末偏移。
pub fn NormalizedText::original_offset(self : NormalizedText, index : Int) -> Int {
  if index < 0 {
    return 0
  }
  if index >= self.offsets.length() {
    if self.offsets.length() == 0 {
      return 0
    }
    return self.offsets[self.offsets.length() - 1]
  }
  self.offsets[index]
}

///|
/// 截取归一化文本的一段作为证据，最多 `max_len` 个字符。
pub fn NormalizedText::evidence(self : NormalizedText, start : Int, max_len : Int) -> String {
  let chars = self.text.to_array()
  if start < 0 || start >= chars.length() {
    return ""
  }
  let end = if start + max_len > chars.length() {
    chars.length()
  } else {
    start + max_len
  }
  String::from_array(chars[start:end])
}

///|
/// ASCII 词字符：字母、数字、下划线。工具名匹配需要词边界，否则 `read`
/// 会命中 `already`，`delete_email` 会命中 `delete_email_v2`。
pub fn is_word_char(c : Char) -> Bool {
  let u = c.to_int()
  (u >= 0x30 && u <= 0x39) ||
  (u >= 0x41 && u <= 0x5A) ||
  (u >= 0x61 && u <= 0x7A) ||
  u == 0x5F
}

///|
/// 带词边界的子串查找。返回归一化文本中的字符索引。
pub fn NormalizedText::find_all_word(
  self : NormalizedText,
  needle : String,
) -> Array[Int] {
  let hits : Array[Int] = []
  let needle_len = needle.to_array().length()
  if needle_len == 0 {
    return hits
  }
  let chars = self.text.to_array()
  for hit in self.find_all(needle) {
    let before_ok = hit == 0 || !is_word_char(chars[hit - 1])
    let after_pos = hit + needle_len
    let after_ok = after_pos >= chars.length() ||
      !is_word_char(chars[after_pos])
    if before_ok && after_ok {
      hits.push(hit)
    }
  }
  hits
}

///|
/// 截取以 `start` 为中心的证据窗口（向前 `back`、向后 `forward` 个字符）。
pub fn NormalizedText::evidence_window(
  self : NormalizedText,
  start : Int,
  back : Int,
  forward : Int,
) -> String {
  let chars = self.text.to_array()
  let from = if start > back { start - back } else { 0 }
  let to = if start + forward > chars.length() {
    chars.length()
  } else {
    start + forward
  }
  if from >= to {
    return ""
  }
  String::from_array(chars[from:to])
}

///|
/// 在归一化文本中查找所有子串出现位置（ASCII 大小写不敏感）。
pub fn NormalizedText::find_all(self : NormalizedText, needle : String) -> Array[Int] {
  let hay = self.text.to_lower()
  let pat = needle.to_lower()
  let hay_chars = hay.to_array()
  let pat_chars = pat.to_array()
  let hits : Array[Int] = []
  let n = hay_chars.length()
  let m = pat_chars.length()
  if m == 0 || m > n {
    return hits
  }
  let mut i = 0
  while i + m <= n {
    let mut matched = true
    let mut j = 0
    while j < m {
      if hay_chars[i + j] != pat_chars[j] {
        matched = false
        break
      }
      j += 1
    }
    if matched {
      hits.push(i)
    }
    i += 1
  }
  hits
}
