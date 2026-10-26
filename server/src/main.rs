//! Pek.ROutGuard Server CLI。
//!
//! 命令：
//! - `-run`（默认）：启动服务（面板 + 客户端接口）
//! - `-status`：查看配置、密钥、数据库统计
//! - `-preview <file>`：读取容器明文头（公司提示 / 规则集 / 创建者）
//! - `-help` / `-version`
//!
//! 服务化 / 星尘注册 / 自升级在 M2 接入（`dhrust::service` / `staragent` / `upgrade`）。

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use dhrust::logs::LogLevel;
use dhrust::net::http::HttpServerOptions;
use dhrust::net::listener::Listener;

use pek_outguard_core::container;
use pek_outguard_server::{VERSION, app::App, base_dir, config, db, keys, panel};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let base = base_dir();
    let _ = std::fs::create_dir_all(&base);

    let text_only = matches!(
        args.first().map(String::as_str),
        Some(
            "-status" | "--status" | "-preview" | "--preview" | "-help" | "--help" | "-h"
                | "-version" | "--version"
        )
    );
    dhrust::logs::init_console_and_file(base.join("Log"), !text_only, LogLevel::Info);
    dhrust::info!(
        "Pek.ROutGuard Server v{VERSION} 执行：args={args:?} 基目录={}",
        base.display()
    );
    dhrust::logs::flush();

    let code = match args.first().map(String::as_str) {
        Some("-help" | "--help" | "-h") => {
            print_help();
            0
        }
        Some("-status" | "--status") => status_command(&base),
        Some("-preview" | "--preview") => match args.get(1) {
            Some(path) => preview_command(path),
            None => {
                eprintln!("用法：pek-outguard-server -preview <容器文件>");
                2
            }
        },
        Some("-version" | "--version") => {
            println!("Pek.ROutGuard Server v{VERSION}");
            0
        }
        Some("-run" | "--run") | None => run_command(base.clone()),
        Some(other) => {
            eprintln!("未知参数：{other}（用 -help 查看用法）");
            2
        }
    };

    dhrust::logs::flush();
    ExitCode::from(code)
}

fn print_help() {
    println!(
        "Pek.ROutGuard Server v{VERSION} —— 企业文件防泄漏管理端\n\
         \n\
         用法：\n\
         \x20 pek-outguard-server                 启动服务（读 Config/OutGuard.toml）\n\
         \x20 pek-outguard-server -status         查看配置、主密钥与数据库统计\n\
         \x20 pek-outguard-server -preview <file> 读取加密容器明文头\n\
         \x20 pek-outguard-server -version        打印版本\n\
         \x20 pek-outguard-server -help           显示帮助\n\
         \n\
         首次启动：自动生成 Config/OutGuard.toml、Data/outguard.db、Data/master.key\n\
         面板默认账号：admin/admin（启动后请尽快改密）\n\
         客户端接口：/api/client/register / heartbeat / policy / events"
    );
}

fn bind_address(host: &str, allow_remote: bool, port: u16) -> String {
    let trimmed = host.trim();
    let host = if trimmed.is_empty() {
        "127.0.0.1"
    } else if allow_remote && (trimmed == "127.0.0.1" || trimmed == "localhost") {
        // 允许远程但配置仍写回环时，按"监听全部网卡"理解（与 Pek 系其它服务一致）。
        "0.0.0.0"
    } else {
        trimmed
    };
    format!("{host}:{port}")
}

fn run_command(base: PathBuf) -> u8 {
    let app = match App::open(&base) {
        Ok(app) => app,
        Err(e) => {
            dhrust::error!("启动失败：{e}");
            eprintln!("启动失败：{e}");
            return 1;
        }
    };

    match app.ensure_default_account() {
        Ok(true) => dhrust::warn!("面板账号已初始化为 admin/admin —— 请尽快改密"),
        Ok(false) => {}
        Err(e) => dhrust::error!("面板账号初始化失败：{e}"),
    }

    let server = app.server();
    let address = bind_address(&server.host, server.allow_remote, server.port);
    let handler = panel::build_router(Arc::clone(&app)).into_handler();
    let options = HttpServerOptions {
        thread_per_connection: true,
        ..Default::default()
    };
    let listener = match Listener::bind(&address, "outguard-web", handler, options) {
        Ok(listener) => listener,
        Err(e) => {
            dhrust::error!("监听失败（{address}）：{e}");
            eprintln!("监听失败（{address}）：{e}");
            return 1;
        }
    };

    let local = listener.addr().to_string();
    dhrust::info!("Pek.ROutGuard Server v{VERSION} 已启动：http://{local}");
    dhrust::info!("面板：http://{local}/（默认 admin/admin）");
    dhrust::info!("公司：{}", server.company_name);
    if server.watch_roots.is_empty() {
        dhrust::warn!("WatchRoots 为空：客户端不会监控任何目录（请在 Config/OutGuard.toml 配置）");
    }
    println!("Pek.ROutGuard Server v{VERSION}");
    println!("监听：http://{local}/");
    println!("公司：{}", server.company_name);
    println!("按 Ctrl+C 退出");

    // 监听在专用线程运行；主线程保活（M2 接服务化与优雅停机）。
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn status_command(base: &std::path::Path) -> u8 {
    let config = config::load(base);
    let server = &config.value().server;
    println!("Pek.ROutGuard Server v{VERSION}");
    println!("基目录：{}", base.display());
    println!(
        "监听：{}:{}（AllowRemote={}）",
        server.host, server.port, server.allow_remote
    );
    println!(
        "面板账号：{}（鉴权 {}，密码{}）",
        server.web_user_name,
        server.web_auth_level,
        if server.web_password_hash.is_empty() {
            "未初始化（启动时设为 admin/admin）"
        } else {
            "已设置"
        }
    );
    println!("公司：{}", server.company_name);
    println!(
        "监控根：{}",
        if server.watch_roots.is_empty() {
            "（空：客户端不监控）".to_string()
        } else {
            server.watch_roots.join(", ")
        }
    );
    println!(
        "主密钥：{}（{}）",
        keys::key_path(base).display(),
        if keys::key_path(base).is_file() {
            "已存在"
        } else {
            "未生成（首次启动自动生成）"
        }
    );

    match db::open(base) {
        Ok(store) => {
            let (total, online, pending) = db::client_stats(&store).unwrap_or((0, 0, 0));
            println!("终端：{total}（在线 {online}，待准入 {pending}）");
            println!(
                "规则集：{}",
                db::list_policies(&store)
                    .map(|items| items.len())
                    .unwrap_or(0)
            );
            println!("事件：{}", db::event_count(&store).unwrap_or(0));
        }
        Err(e) => println!("数据库不可用：{e}"),
    }
    0
}

fn preview_command(path: &str) -> u8 {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("打开文件失败：{e}");
            return 1;
        }
    };
    let mut reader = std::io::BufReader::new(file);
    match container::read_header(&mut reader) {
        Ok(header) => {
            println!("容器类型：OGD1");
            println!("公司：{}", header.company);
            println!("密级：{}", header.classification);
            println!("提示：{}", header.notice);
            println!(
                "原始文件：{}（{} 字节）",
                header.original_name, header.original_size
            );
            println!("规则集：{} v{}", header.policy_id, header.policy_version);
            println!("创建者：{}", header.creator);
            println!("创建时间：{}", header.created_at);
            0
        }
        Err(e) => {
            eprintln!("不是有效的 OutGuard 容器：{e}");
            1
        }
    }
}
