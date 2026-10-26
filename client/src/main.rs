//! Pek.ROutGuard Client CLI。
//!
//! **定位**：安装后常驻、按服务端策略自动加密；**可配置、不可停止、不可卸载**
//! （配置入口只改"连哪个服务端、用哪个账号"，不提供暂停保护/退出/卸载；卸载需服务端令牌，M2）。
//!
//! 命令：
//! - `status` 查看配置与同步状态
//! - `config show` / `config set --server URL [--enroll CODE] [--account USER] [--password PASS] [--temp DIR]`
//! - `register` 注册终端（设备模式或账号模式）
//! - `sync` 拉取策略与密钥
//! - `heartbeat` 发送一次心跳
//! - `encrypt <file>` / `decrypt <file> [--out DIR]` / `open <file>`
//! - `version` / `help`
//!
//! 服务化（Windows 服务、防退出、托盘、文件监控）在 M2 接入。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dhrust::logs::LogLevel;
use pek_outguard_client::api::Api;
use pek_outguard_client::config::{self, ClientConfig};
use pek_outguard_client::{VERSION, base_dir, ops, runtime, service, state};
use pek_outguard_core::machine;
use pek_outguard_core::protocol::{HardwareInfo, HeartbeatRequest, RegisterRequest};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let base = base_dir();
    let _ = std::fs::create_dir_all(&base);
    dhrust::logs::init_console_and_file(base.join("Log"), false, LogLevel::Info);
    dhrust::info!("Pek.ROutGuard Client v{VERSION} 执行：args={args:?} 基目录={}", base.display());
    dhrust::logs::flush();

    let code = match args.first().map(String::as_str) {
        None | Some("status") => status_command(&base),
        Some("config") => config_command(&base, args.get(1..).unwrap_or(&[])),
        Some("register") => register_command(&base),
        Some("sync") => sync_command(&base),
        Some("heartbeat") => heartbeat_command(&base),
        Some("encrypt") => encrypt_command(&base, args.get(1).map(String::as_str)),
        Some("decrypt") => decrypt_command(&base, args.get(1..).unwrap_or(&[])),
        Some("open") => open_command(&base, args.get(1).map(String::as_str)),
        Some("install") => install_command(&base),
        Some("uninstall") => {
            uninstall_command(&base, args.iter().any(|arg| arg == "--force"))
        }
        Some("start") => service_action(&base, "start"),
        Some("stop") => service_action(&base, "stop"),
        Some("restart") => service_action(&base, "restart"),
        Some("run") => run_command(&base),
        Some("-s") | Some("--service") | Some("service") => service_mode(&base),
        Some("version") | Some("--version") | Some("-version") => {
            println!("Pek.ROutGuard Client v{VERSION}");
            0
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            0
        }
        Some(other) => {
            eprintln!("未知命令：{other}（用 help 查看用法）");
            2
        }
    };

    dhrust::logs::flush();
    ExitCode::from(code)
}

fn print_help() {
    println!(
        "Pek.ROutGuard Client v{VERSION} —— 企业文件防泄漏终端\n\
         \n\
         用法：\n\
         \x20 pek-outguard-client status                 查看配置与同步状态\n\
         \x20 pek-outguard-client config show            显示当前配置\n\
         \x20 pek-outguard-client config set --server http://10.0.0.5:5600 \\\n\
         \x20     [--enroll CODE] [--account USER] [--password PASS] [--temp DIR]\n\
         \x20 pek-outguard-client register               注册终端（设备模式/账号模式）\n\
         \x20 pek-outguard-client sync                   拉取策略与密钥\n\
         \x20 pek-outguard-client heartbeat              发送一次心跳\n\
         \x20 pek-outguard-client encrypt <file>         按策略加密文件\n\
         \x20 pek-outguard-client decrypt <file> [--out DIR]  解密到受控目录\n\
         \x20 pek-outguard-client open <file>            解密并用默认程序打开\n\
         \x20 pek-outguard-client version / help\n\
         \n\
         服务化（需管理员权限）：\n\
         \x20 install / uninstall [--force] / start / stop / restart / run / status\n\
         \n\
         说明：客户端可配置但**不可停止、不可卸载**；卸载默认需服务端允许（AllowUninstall）。"
    );
}

// ————— status / config —————

fn status_command(base: &Path) -> u8 {
    let config = config::load(base);
    let section = &config.value().client;
    let state = state::load(base);

    println!("Pek.ROutGuard Client v{VERSION}");
    println!("基目录：{}", base.display());
    println!("服务端：{}", section.server_url);
    println!(
        "账号：{}",
        if section.account.trim().is_empty() {
            "（设备模式）"
        } else {
            section.account.as_str()
        }
    );
    println!(
        "密码：{}",
        if section.password.is_empty() {
            "未设置"
        } else {
            "已保存（enc:v1 加密）"
        }
    );
    println!(
        "终端：{}",
        if state.client_id.is_empty() {
            "未注册"
        } else {
            state.client_id.as_str()
        }
    );
    println!(
        "状态：{}",
        if state.status.is_empty() {
            "-"
        } else {
            state.status.as_str()
        }
    );
    println!(
        "策略版本：{}（最近同步：{}）",
        state.policy_version,
        if state.last_sync.is_empty() {
            "-"
        } else {
            state.last_sync.as_str()
        }
    );
    println!("待上报事件：{}", state.pending_events.len());
    println!("受控临时目录：{}", config::temp_dir(section).display());
    println!(
        "服务：{}（{}）",
        service::SERVICE_NAME,
        service::query(base).text()
    );
    println!("提示：客户端不可停止、不可卸载；卸载需服务端授权。");
    0
}

fn config_command(base: &Path, args: &[String]) -> u8 {
    match args.first().map(String::as_str) {
        Some("show") | None => {
            let config = config::load(base);
            let section = &config.value().client;
            println!("配置文件：{}", config::config_path(base).display());
            println!("ServerUrl = \"{}\"", section.server_url);
            println!("EnrollCode = \"{}\"", section.enroll_code);
            println!("Account = \"{}\"", section.account);
            println!(
                "Password = \"{}\"",
                if section.password.is_empty() {
                    ""
                } else {
                    "enc:v1:***"
                }
            );
            println!("TempDir = \"{}\"", section.temp_dir);
            println!("WatchRoots = {:?}", section.watch_roots);
            println!("ReportIntervalSecs = {}", section.report_interval_secs);
            0
        }
        Some("set") => config_set(base, &args[1..]),
        Some(other) => {
            eprintln!("未知 config 子命令：{other}（可用：show / set）");
            2
        }
    }
}

fn config_set(base: &Path, args: &[String]) -> u8 {
    let mut section = config::load(base).value().client.clone();
    let mut index = 0usize;
    while index < args.len() {
        let key = args[index].as_str();
        let value = args.get(index + 1).cloned().unwrap_or_default();
        match key {
            "--server" => section.server_url = value.trim().to_string(),
            "--enroll" => section.enroll_code = value.trim().to_string(),
            "--account" => section.account = value.trim().to_string(),
            "--password" => section.password = config::encrypt_password(&value),
            "--temp" => section.temp_dir = value.trim().to_string(),
            other => {
                eprintln!("未知参数：{other}");
                return 2;
            }
        }
        index += 2;
    }

    if section.server_url.trim().is_empty() {
        eprintln!("ServerUrl 不能为空");
        return 2;
    }
    let config = ClientConfig {
        client: section.clone(),
    };
    match config::save(base, &config) {
        Ok(path) => {
            println!("配置已保存：{}", path.display());
            println!("服务端：{}", section.server_url);
            println!(
                "下一步：pek-outguard-client register（注册后需管理员在面板准入）"
            );
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

// ————— register / sync / heartbeat —————

fn current_section(base: &Path) -> Result<config::ClientSection, String> {
    Ok(config::load(base).value().client.clone())
}

fn build_api(section: &config::ClientSection) -> Result<Api, String> {
    Api::new(&section.server_url)
}

fn now_text() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn register_command(base: &Path) -> u8 {
    let section = match current_section(base) {
        Ok(section) => section,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let api = match build_api(&section) {
        Ok(api) => api,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    let mut state = state::load(base);
    let seed = state::ensure_device_seed(&mut state);
    let device = match runtime::seed_key(&seed) {
        Ok(device) => device,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };

    let guid = dhrust::sys::machine::machine_guid().unwrap_or_default();
    let host = dhrust::sys::machine::hostname();
    let cpu = dhrust::sys::machine::cpu_model().unwrap_or_default();
    let machine_id = machine::machine_id(&guid, &host, &cpu)
        .unwrap_or_else(|_| dhrust::random::hex(16));

    let memory_mb = dhrust::sys::machine::memory_info()
        .map(|(total, _)| total / (1024 * 1024))
        .unwrap_or(0);

    let request = RegisterRequest {
        machine_id: machine_id.clone(),
        hostname: host,
        os: dhrust::sys::machine::os_description(),
        client_version: VERSION.to_string(),
        public_key: device.public_key_b64(),
        enroll_code: section.enroll_code.clone(),
        hardware: Some(HardwareInfo {
            cpu,
            memory_mb,
            disk_total_gb: 0,
            os_build: String::new(),
            domain: std::env::var("USERDOMAIN").unwrap_or_default(),
        }),
        logged_user: dhrust::sys::machine::user_name(),
        ip: String::new(),
        mac: String::new(),
        installed_at: chrono::Utc::now().timestamp(),
        account: section.account.clone(),
        password: config::decrypt_password(&section.password),
    };

    match api.register(&request) {
        Ok(response) => {
            state.client_id = response.client_id.clone();
            state.client_token = response.client_token.clone();
            state.status = format!("{:?}", response.status).to_lowercase();
            if let Err(e) = state::save(base, &state) {
                eprintln!("{e}");
                return 1;
            }
            println!("注册成功：clientId={} 状态={}", response.client_id, state.status);
            if state.status == "pending" {
                println!("终端待管理员在面板准入（准入后才能同步策略）。");
            }
            0
        }
        Err(e) => {
            eprintln!("注册失败：{e}");
            1
        }
    }
}

fn sync_command(base: &Path) -> u8 {
    let section = match current_section(base) {
        Ok(section) => section,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let api = match build_api(&section) {
        Ok(api) => api,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let mut state = state::load(base);
    if state.client_id.is_empty() || state.client_token.is_empty() {
        eprintln!("尚未注册（先执行 register）");
        return 1;
    }

    match api.policy(&state.client_id, &state.client_token) {
        Ok(bundle) => {
            println!(
                "策略已同步：version={} 规则集={} 密钥={} 监控根={}",
                bundle.version,
                bundle.policy_sets.len(),
                bundle.wrapped_keys.len(),
                bundle.watch_roots.len()
            );
            for policy in &bundle.policy_sets {
                println!(
                    "  · {}（{}）v{} 规则 {} 条，默认 {}",
                    policy.name,
                    policy.id,
                    policy.version,
                    policy.rules.len(),
                    policy.default_action.as_str()
                );
            }
            state.policy_version = bundle.version;
            state.policy = Some(bundle);
            state.last_sync = now_text();
            state.status = "active".into();
            if let Err(e) = state::save(base, &state) {
                eprintln!("{e}");
                return 1;
            }
            if state.policy.as_ref().is_some_and(|bundle| bundle.watch_roots.is_empty()) {
                println!("注意：服务端未配置 WatchRoots，客户端暂不会自动监控目录（可用 encrypt 手动加密）。");
            }
            0
        }
        Err(e) => {
            eprintln!("同步失败：{e}");
            if e.contains("待管理员准入") {
                println!("提示：请管理员在面板「终端」页把该终端设为 active。");
            }
            1
        }
    }
}

fn heartbeat_command(base: &Path) -> u8 {
    let section = match current_section(base) {
        Ok(section) => section,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let api = match build_api(&section) {
        Ok(api) => api,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let mut state = state::load(base);
    if state.client_id.is_empty() {
        eprintln!("尚未注册（先执行 register）");
        return 1;
    }

    let request = HeartbeatRequest {
        client_id: state.client_id.clone(),
        client_version: VERSION.to_string(),
        policy_version: state.policy_version,
        hostname: None,
        logged_user: None,
        os: None,
        health: None,
        anomalies: None,
        ip: None,
        mac: None,
        hardware: None,
    };
    match api.heartbeat(&state.client_id.clone(), &state.client_token.clone(), &request) {
        Ok(response) => {
            state.last_heartbeat = now_text();
            let _ = state::save(base, &state);
            println!(
                "心跳成功：期望策略版本={} 指令={:?}",
                response.policy_version, response.commands
            );
            if response.policy_version != state.policy_version {
                println!("策略版本不一致，请执行 sync。");
            }
            0
        }
        Err(e) => {
            eprintln!("心跳失败：{e}");
            1
        }
    }
}

// ————— encrypt / decrypt / open —————

fn encrypt_command(base: &Path, path: Option<&str>) -> u8 {
    let Some(path) = path else {
        eprintln!("用法：pek-outguard-client encrypt <file>");
        return 2;
    };
    let state = state::load(base);
    if state.policy.is_none() {
        eprintln!("尚未同步策略（先执行 sync）");
        return 1;
    }
    match ops::encrypt_file(&state, Path::new(path)) {
        Ok(outcome) => {
            println!(
                "已加密：{} → {}（规则集 {} / 规则 {}，明文 {} 字节）",
                path,
                outcome.output.display(),
                outcome.policy_id,
                outcome.rule_id,
                outcome.plain_size
            );
            0
        }
        Err(e) => {
            eprintln!("加密失败：{e}");
            1
        }
    }
}

fn decrypt_command(base: &Path, args: &[String]) -> u8 {
    let mut path: Option<&str> = None;
    let mut out_dir: Option<String> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                out_dir = args.get(index + 1).cloned();
                index += 2;
            }
            other => {
                path = Some(other);
                index += 1;
            }
        }
    }
    let Some(path) = path else {
        eprintln!("用法：pek-outguard-client decrypt <file> [--out DIR]");
        return 2;
    };

    let section = match current_section(base) {
        Ok(section) => section,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let state = state::load(base);
    let target = match out_dir {
        Some(dir) => PathBuf::from(dir),
        None => config::temp_dir(&section),
    };
    match ops::decrypt_file(&state, Path::new(path), &target) {
        Ok(output) => {
            println!("已解密：{}", output.display());
            0
        }
        Err(e) => {
            eprintln!("解密失败：{e}");
            1
        }
    }
}

fn open_command(base: &Path, path: Option<&str>) -> u8 {
    let Some(path) = path else {
        eprintln!("用法：pek-outguard-client open <file>");
        return 2;
    };
    let section = match current_section(base) {
        Ok(section) => section,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let state = state::load(base);
    let temp = config::temp_dir(&section);
    match ops::open_file(&state, Path::new(path), &temp) {
        Ok(output) => {
            println!("已解密并交给默认程序：{}", output.display());
            println!("提示：受控临时目录为 {}（关闭程序后可删除）", temp.display());
            0
        }
        Err(e) => {
            eprintln!("打开失败：{e}");
            1
        }
    }
}

// ————— 服务化 —————

fn install_command(base: &Path) -> u8 {
    match service::install(base, true) {
        Ok(()) => {
            println!("服务已安装并启动：{}", service::SERVICE_NAME);
            println!("已设置失败恢复策略（崩溃 5s/10s/30s 自动重启）。");
            println!("查看状态：pek-outguard-client status");
            0
        }
        Err(e) => {
            eprintln!("安装失败（需管理员权限）：{e}");
            1
        }
    }
}

fn uninstall_command(base: &Path, force: bool) -> u8 {
    let state = state::load(base);
    let allowed = state
        .policy
        .as_ref()
        .map(|bundle| bundle.allow_uninstall)
        .unwrap_or(false);
    if !allowed && !force {
        eprintln!("⚠ 卸载被拒绝：需管理员在服务端配置 AllowUninstall = true（客户端下次同步后生效）。");
        eprintln!("  确需强制卸载请使用 --force（会记录审计，不推荐）。");
        return 1;
    }
    if force && !allowed {
        dhrust::warn!("强制卸载（--force）：未获服务端授权");
    }
    match service::uninstall(base) {
        Ok(()) => {
            println!("服务已卸载：{}", service::SERVICE_NAME);
            0
        }
        Err(e) => {
            eprintln!("卸载失败（需管理员权限）：{e}");
            1
        }
    }
}

fn service_action(base: &Path, action: &str) -> u8 {
    let manager = service::manager(base);
    let result = match action {
        "start" => manager.start(),
        "stop" => manager.stop(),
        "restart" => manager.restart(),
        _ => return 2,
    };
    match result {
        Ok(()) => {
            println!("服务 {action} 成功");
            0
        }
        Err(e) => {
            eprintln!("服务 {action} 失败：{e}");
            1
        }
    }
}

fn run_command(base: &Path) -> u8 {
    println!("客户端前台运行（Ctrl+C 退出）…");
    match runtime::run(base) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("运行失败：{e}");
            1
        }
    }
}

fn service_mode(base: &Path) -> u8 {
    #[cfg(windows)]
    {
        let base_owned = base.to_path_buf();
        dhrust::service::windows::run_as_service(
            service::SERVICE_NAME,
            runtime::request_stop,
            move || {
                if let Err(e) = runtime::run(&base_owned) {
                    dhrust::error!("客户端运行失败：{e}");
                }
            },
        );
        0
    }
    #[cfg(not(windows))]
    {
        run_command(base)
    }
}

// ————— 辅助 —————

// 设备种子解码与密钥构造已下沉 `runtime`（避免两处实现漂移）。
