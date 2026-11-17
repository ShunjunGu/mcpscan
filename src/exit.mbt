// 进程退出码。
//
// CI 门禁依赖退出码：发现有 high/critical 时必须返回 1，否则流水线永远
// 绿灯。MoonBit 没有内建的非零退出机制，native/llvm 目标通过 C `exit()`
// 实现；其他目标降级为 abort（单一非零码），CLI 实际只在 native 使用。

///|
#cfg(any(target="native", target="llvm"))
extern "c" fn exit_with(code : Int32) = "exit"

///|
#cfg(not(any(target="native", target="llvm")))
fn exit_with(code : Int32) -> Unit {
  let _ = code
  abort("mcpscan: cannot set a specific exit code on this target")
}

///|
/// 退出码语义：0 无阻断、1 存在 high/critical、2 用法或读取失败。
pub fn exit_ok() -> Unit {
  exit_with(0)
}

///|
pub fn exit_blocked() -> Unit {
  exit_with(1)
}

///|
pub fn exit_error() -> Unit {
  exit_with(2)
}

///|
/// 是否存在阻断级发现（high / critical）。
pub fn has_blocking(findings : Array[Finding]) -> Bool {
  for f in findings {
    match f.severity {
      Critical | High => return true
      _ => ()
    }
  }
  false
}
