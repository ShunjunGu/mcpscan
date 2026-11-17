// thin executable shell: 参数解析与扫描逻辑都在库包，这里只做进程入口。
// @env.args()[0] 是 exe 路径，子命令从 [1] 开始。

///|
fn main {
  let args = @env.args()
  if args.length() < 2 {
    @mcpscan.print_usage()
    return
  }
  let cmd = args[1]
  if cmd == "version" || cmd == "--version" || cmd == "-v" {
    println("mcpscan \{@mcpscan.version()}")
  } else if cmd == "rules" {
    @mcpscan.print_rules()
  } else if cmd == "scan" {
    @mcpscan.run_scan(args[2:])
  } else if cmd == "baseline" {
    @mcpscan.run_baseline(args[2:])
  } else {
    println("unknown command: \{cmd}")
    @mcpscan.print_usage()
  }
}
