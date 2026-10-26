//! Pek.ROutGuard Client（终端）。
//!
//! 当前为 **M1 骨架**：命令面 + 容器头读取（"已装客户端能看到文件属于哪条规则/哪个公司"）。
//! 业务实现按 `docs/架构设计.md` 第 7 节推进：服务化 → 注册 → 策略缓存 → 监控 → 加密 → 受控打开。
//!
//! 命令：
//! - `status`：版本与配置路径
//! - `open <file>`：打开容器（M1 骨架阶段仅显示头部信息；完整解密需策略密钥）
//! - `help`：帮助

use std::process::ExitCode;

use pek_outguard_core::container;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut iter = args.iter();
    match iter.next().map(String::as_str) {
        None | Some("status") => {
            print_status();
            ExitCode::SUCCESS
        }
        Some("open") => match iter.next() {
            Some(path) => open_container(path),
            None => {
                eprintln!("用法：pek-outguard-client open <容器文件>");
                ExitCode::from(2)
            }
        },
        Some("version") | Some("--version") | Some("-version") => {
            println!(
                "{} {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("未知命令：{other}");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_status() {
    println!("Pek.ROutGuard Client {}", env!("CARGO_PKG_VERSION"));
    println!("容器扩展名：{}", pek_outguard_core::CONTAINER_EXT);
    println!("阶段：M1 骨架（服务化/监控/加密见 docs/架构设计.md）");
}

fn print_help() {
    println!("Pek.ROutGuard Client {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("用法：");
    println!("  pek-outguard-client status            查看版本");
    println!("  pek-outguard-client open <file>       打开加密容器");
    println!("  pek-outguard-client version           打印版本");
    println!("  pek-outguard-client help              显示帮助");
}

/// 打开容器（骨架阶段：展示头部信息）。
fn open_container(path: &str) -> ExitCode {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("打开文件失败：{e}");
            return ExitCode::from(1);
        }
    };

    let mut reader = std::io::BufReader::new(file);
    match container::read_header(&mut reader) {
        Ok(header) => {
            println!("公司：{}", header.company);
            println!("密级：{}", header.classification);
            println!("原始文件：{}（{} 字节）", header.original_name, header.original_size);
            println!("规则集：{} v{}（规则 {}）", header.policy_id, header.policy_version, header.rule_id);
            println!("创建者：{} / 终端 {}", header.creator, header.client_id);
            println!("创建时间：{}", header.created_at);
            println!();
            println!("提示：{}", header.notice);
            println!();
            println!("（骨架阶段：完整解密打开将在 M1 实现，需要服务端下发的策略密钥）");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("不是有效的 OutGuard 容器：{e}");
            ExitCode::from(1)
        }
    }
}
