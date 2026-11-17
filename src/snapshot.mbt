// 快照解析：把 `tools/list` 的 JSON 快照解析为 ToolDef 数组。
//
// 为什么保留 schema 的原始 JSON 文本而不是结构化：静态审计关心"模型实际
// 看到的字符串"，字段顺序、未知字段、嵌套 description 都是攻击面；过早
// 结构化会丢失这些信息。

///|
/// 一次快照。`server` 可以为空——用户经常只保存 tools/list 的返回体。
pub struct Snapshot {
  server : String
  tools : Array[ToolDef]
}

///|
fn field_string(obj : Map[String, Json], key : String) -> String {
  match obj.get(key) {
    Some(String(s)) => s
    _ => ""
  }
}

///|
fn field_json_text(obj : Map[String, Json], key : String) -> String {
  match obj.get(key) {
    Some(v) => v.stringify()
    _ => ""
  }
}

///|
/// 解析快照文本。返回 `Err` 而不是 raise：CLI 需要区分"读失败"与"格式错误"，
/// 并映射到不同的退出码。
pub fn parse_snapshot(text : String) -> Result[Snapshot, String] {
  let root = @json.parse(text) catch {
    _ => return Err("invalid JSON")
  }
  let root_obj = match root {
    Object(o) => o
    _ => return Err("snapshot root must be a JSON object")
  }
  let server = field_string(root_obj, "server")
  let tools_json = match root_obj.get("tools") {
    Some(Array(a)) => a
    Some(_) => return Err("`tools` must be an array")
    None => return Err("missing `tools`")
  }
  let tools : Array[ToolDef] = []
  for entry in tools_json {
    let obj = match entry {
      Object(o) => o
      _ => return Err("each tool entry must be an object")
    }
    tools.push(
      {
        server_name: server,
        name: field_string(obj, "name"),
        description: field_string(obj, "description"),
        input_schema: field_json_text(obj, "inputSchema"),
        output_schema: field_json_text(obj, "outputSchema"),
        annotations: field_json_text(obj, "annotations"),
      },
    )
  }
  Ok({ server, tools })
}
