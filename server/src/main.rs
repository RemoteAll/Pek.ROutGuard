//! Pek.ROutGuard Server（管理端）。
//!
//! 当前为 **M1 骨架**：命令面 + 容器头预览（用于"没装客户端时被服务端识别"的演示）。
//! 业务实现按 `docs/架构设计.md` 第 6 节推进：配置 → 数据库 → 密钥 → 路由 → 监听。
//!
//! 命令：
//! - `-status`：版本、数据目录、默认端口
//! - `-preview <file>`：读取并打印容器明文头（不校验密钥）
//! - `-help`：帮助

use std::path::PathBuf;
use std::process::ExitCode;

use pek_outguard_core::container;

/// 面板默认端口（可配）。
const DEFAULT_PORT: u16 = 5600;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut iter = args.iter();
    match iter.next().map(String::as_str) {
        None | Some("-status") => {
            print_status();
            ExitCode::SUCCESS
        }
        Some("-preview") => match iter.next() {
            Some(path) => preview(path),
            None => {
                eprintln!("用法：pek-outguard-server -preview <容器文件>");
                ExitCode::from(2)
            }
        },
        Some("-version") | Some("--version") => {
            println!(
                "{} {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        Some("-help") | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("未知参数：{other}");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_status() {
    println!("Pek.ROutGuard Server {}", env!("CARGO_PKG_VERSION"));
    println!("数据目录：{}", data_dir().display());
    println!("默认面板端口：{DEFAULT_PORT}");
    println!("阶段：M1 骨架（业务实现见 docs/架构设计.md）");
}

fn print_help() {
    println!("Pek.ROutGuard Server {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("用法：");
    println!("  pek-outguard-server -status              查看版本与路径");
    println!("  pek-outguard-server -preview <file>      读取容器明文头（含公司防泄密信息）");
    println!("  pek-outguard-server -version             打印版本");
    println!("  pek-outguard-server -help                显示帮助");
}

/// 读取并打印容器明文头。
fn preview(path: &str) -> ExitCode {
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
            println!("容器类型：OGD1");
            println!("公司：{}", header.company);
            println!("密级：{}", header.classification);
            println!("提示：{}", header.notice);
            println!("原始文件：{}（{} 字节）", header.original_name, header.original_size);
            println!("规则集：{} v{}", header.policy_id, header.policy_version);
            println!("创建者：{}", header.creator);
            println!("创建时间：{}", header.created_at);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("不是有效的 OutGuard 容器：{e}");
            ExitCode::from(1)
        }
    }
}

fn data_dir() -> PathBuf {
    match std::env::current_exe() {
        Ok(exe) => exe.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")),
        Err(_) => PathBuf::from("."),
    }
    .join("Data")
}
