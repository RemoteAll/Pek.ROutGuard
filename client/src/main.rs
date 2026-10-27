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
use pek_outguard_client::{
    VERSION, assoc, base_dir, opensession, ops, projfs, runtime, safety, secure_area, service, state, watch,
};
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
        Some("sessions") => sessions_command(&base),
        Some("secure-area") => secure_area_command(&base, args.get(1..).unwrap_or(&[])),
        Some("mode") => mode_command(&base, args.get(1..).unwrap_or(&[])),
        Some("install") => install_command(&base),
        Some("uninstall") => {
            uninstall_command(&base, args.iter().any(|arg| arg == "--force"))
        }
        Some("start") => service_action(&base, "start"),
        Some("stop") => service_action(&base, "stop"),
        Some("restart") => service_action(&base, "restart"),
        Some(action @ ("register-assoc" | "unregister-assoc")) => assoc_command(action),
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
         \x20     [--enroll CODE] [--account USER] [--password PASS] [--temp DIR] \\\n\
         \x20     [--secure-areas D:\\SecureWork;E:\\Secure2] [--recovery-days 7]\n\
         \x20 pek-outguard-client register               注册终端（设备模式/账号模式）\n\
         \x20 pek-outguard-client sync                   拉取策略与密钥\n\
         \x20 pek-outguard-client heartbeat              发送一次心跳\n\
         \x20 pek-outguard-client encrypt <file>         按策略加密文件\n\
         \x20 pek-outguard-client decrypt <file> [--out DIR]  解密到受控目录\n\
         \x20 pek-outguard-client open <file>            受控打开（编辑保存后自动回写成密文）\n\
         \x20 pek-outguard-client sessions              列出受控打开会话\n\
         \x20 pek-outguard-client mode [show|live --confirm|dry-run]  运行模式（默认演练，不动文件）\n\
         \x20 pek-outguard-client register-assoc        注册 .ogd 关联（双击直接打开，免管理员）\n\
         \x20 pek-outguard-client unregister-assoc      解除 .ogd 关联\n\
         \x20 pek-outguard-client version / help\n\
         \n\
         服务化（需管理员权限）：\n\
         \x20 install / uninstall [--force] / start / stop / restart / run / status\n\
         \n\
         说明：\n\
         \x20 · 客户端可配置但**不可停止、不可卸载**；卸载默认需服务端允许（AllowUninstall）。\n\
         \x20 · 日常使用请用 open（受控打开）：明文只在受控临时目录，保存后自动加密回 .ogd。\n\
         \x20 · 需要**拿走干净明文**（外发/存档）属高危操作，需联网提交审批，不能用 open 代替。"
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
    println!("受控打开会话：{} 个", opensession::load(base).len());
    println!(
        "运行模式：{}",
        if section.is_dry_run() {
            "演练（dry_run）—— 不会加密/移动/删除任何文件"
        } else {
            "实盘（live）—— 受控目录内文件会被真正加密"
        }
    );
    println!(
        "安全阀：危险监控根 {}",
        if section.allow_risky_roots {
            "已放行（AllowRiskyRoots = true，风险自负）"
        } else {
            "已启用（桌面/文档/下载/盘符根自动跳过）"
        }
    );
    println!("原文件回收保留：{} 天", section.recovery_keep_days);
    println!(
        "安全区（透明加密）：{}",
        if section.secure_areas.is_empty() {
            "未配置（用 config set --secure-areas 添加）".to_string()
        } else {
            format!(
                "{} 个｜{}｜ProjFS {}",
                section.secure_areas.len(),
                section.secure_areas.join("；"),
                if projfs::is_supported() { "可用" } else { "不支持" }
            )
        }
    );

    // 离线状态：本地缓存策略照常生效，超宽限才拒绝解密。
    let now = chrono::Utc::now().timestamp();
    let offline_secs = state.offline_secs(now);
    let offline_days = state.offline_days(now);
    let grace = state.offline_grace_days();
    println!(
        "连接：{}",
        if offline_secs < 300 {
            "在线（最近 5 分钟内有通信）".to_string()
        } else if offline_secs < 86_400 {
            format!("最近通信 {} 分钟前（离线中，继续用本地缓存策略）", offline_secs / 60)
        } else {
            format!("离线约 {offline_days} 天（继续用本地缓存策略）")
        }
    );
    println!(
        "离线宽限：{}",
        if grace == 0 {
            "不限制（服务端未设置）".to_string()
        } else if state.offline_exceeded(now) {
            format!("{grace} 天 —— 已超期，解密/受控打开被拒绝（自动加密继续）")
        } else {
            format!("{grace} 天（剩余 {} 天）", grace.saturating_sub(offline_days))
        }
    );

    println!("受控临时目录：{}", config::temp_dir(section).display());
    println!(
        "服务：{}（{}）",
        service::SERVICE_NAME,
        service::query(base).text()
    );
    println!("提示：客户端不可停止、不可卸载；卸载需服务端授权。");
    0
}

/// 运行模式：演练（默认，只判定不动文件） / 实盘（真正加密）。
fn mode_command(base: &Path, args: &[String]) -> u8 {
    let loaded = config::load(base);
    let mut config = loaded.value().clone();
    match args.first().map(String::as_str) {
        None | Some("show") => {
            let section = &config.client;
            println!(
                "当前模式：{}",
                if section.is_dry_run() {
                    "演练（dry_run）—— 只判定并记日志，不会加密/移动/删除任何文件"
                } else {
                    "实盘（live）—— 受控目录内的文件会被真正加密"
                }
            );
            println!("原文件回收保留：{} 天（Data/Recovery）", section.recovery_keep_days);
            println!(
                "危险监控根（桌面/文档/盘符根）：{}",
                if section.allow_risky_roots {
                    "已放行（风险自负）"
                } else {
                    "已禁用（默认，安全）"
                }
            );
            0
        }
        Some("live") => {
            if !args.iter().any(|arg| arg == "--confirm") {
                eprintln!("切到实盘后，受控目录里的文件会被真正加密（原文件移入 Data/Recovery 保留）。");
                eprintln!("确认无误请显式加 --confirm：pek-outguard-client mode live --confirm");
                return 2;
            }
            config.client.mode = "live".to_string();
            match config::save(base, &config) {
                Ok(path) => {
                    println!("已切换为实盘模式（{}）。", path.display());
                    println!("需重启服务生效：pek-outguard-client restart");
                    0
                }
                Err(e) => {
                    eprintln!("保存配置失败：{e}");
                    1
                }
            }
        }
        Some("dry-run") | Some("dry_run") | Some("dryrun") => {
            config.client.mode = "dry_run".to_string();
            match config::save(base, &config) {
                Ok(path) => {
                    println!("已切回演练模式（{}）：不会改动任何文件。", path.display());
                    println!("需重启服务生效：pek-outguard-client restart");
                    0
                }
                Err(e) => {
                    eprintln!("保存配置失败：{e}");
                    1
                }
            }
        }
        Some(other) => {
            eprintln!("未知 mode：{other}（可用：show / live --confirm / dry-run）");
            2
        }
    }
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
            println!("SecureAreas = {:?}", section.secure_areas);
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
            // 安全区目录，多个用分号分隔：`--secure-areas "D:\SecureWork;E:\Secure2"`
            "--secure-areas" => {
                section.secure_areas = value
                    .split(';')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect();
            }
            "--recovery-days" => {
                section.recovery_keep_days = value.trim().parse().unwrap_or(7);
            }
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
    let section = match current_section(base) {
        Ok(section) => section,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let options = if section.is_dry_run() {
        println!("当前为演练模式（dry_run）：只判定，不会改动文件。实盘请用 mode live --confirm");
        ops::EncryptOptions::default()
    } else {
        ops::EncryptOptions::live(safety::recovery_dir(base))
    };
    match ops::encrypt_file(&state, Path::new(path), &options) {
        Ok(outcome) if !outcome.applied => {
            println!(
                "演练结果：将会加密 {} → {}（规则集 {} / 规则 {}，明文 {} 字节）；未改动任何文件",
                path,
                outcome.output.display(),
                outcome.policy_id,
                outcome.rule_id,
                outcome.plain_size
            );
            0
        }
        Ok(outcome) => {
            println!(
                "已加密：{} → {}（规则集 {} / 规则 {}，明文 {} 字节；原文件已移入回收区）",
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
    match opensession::open(base, &state, &temp, Path::new(path)) {
        Ok(session) => {
            println!("已解密并交给默认程序：{}", session.temp);
            println!("受控会话：{}", session.session_id);
            println!("提示：{}", opensession::service_hint());
            0
        }
        Err(e) => {
            eprintln!("打开失败：{e}");
            1
        }
    }
}

/// 安全区（ProjFS 透明目录）：`status` 检查可用性，`run` 前台运行便于调测。
fn secure_area_command(base: &Path, args: &[String]) -> u8 {
    let root_arg = arg_value(args, "--root").or_else(|| {
        args.first()
            .filter(|value| !value.starts_with("--"))
            .cloned()
    });
    let probe = projfs::probe();
    if !probe.supported {
        eprintln!("{}", probe.detail);
        return 1;
    }

    match args.first().map(String::as_str) {
        Some("status") => {
            println!("ProjFS：{}", probe.detail);
            match &root_arg {
                Some(root) => match secure_area::check_area(Path::new(root)) {
                    Ok(()) => {
                        println!("安全区 {root}：可直接启用（目录为空）");
                        0
                    }
                    Err(e) => {
                        println!("安全区 {root}：{e}");
                        1
                    }
                },
                None => {
                    println!("用法：secure-area status --root <目录>");
                    0
                }
            }
        }
        Some("run") => {
            let Some(root) = root_arg else {
                eprintln!("用法：secure-area run --root <空目录> [--vault <密文库>]");
                return 2;
            };
            let root = PathBuf::from(root);
            if let Err(e) = secure_area::check_area(&root) {
                eprintln!("无法启用安全区：{e}");
                return 1;
            }
            let state = state::load(base);
            if state.policy.is_none() {
                eprintln!("尚未同步策略（先执行 sync）");
                return 1;
            }
            let name = root
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| "secure".to_string());
            let vault = arg_value(args, "--vault")
                .map(PathBuf::from)
                .unwrap_or_else(|| base.join("Data").join("Vault").join(&name));
            let cache = base.join("Data").join("VaultCache").join(&name);

            let key_state = state.clone();
            let resolver: std::sync::Arc<secure_area::KeyResolver> =
                std::sync::Arc::new(move |policy_id: &str| {
                    ops::policy_key(&key_state, policy_id).ok()
                });
            let bundle = state.policy.clone();
            let policy_id = bundle
                .as_ref()
                .and_then(|b| b.policy_sets.first().map(|policy| policy.id.clone()))
                .unwrap_or_else(|| "default".to_string());
            let area = match secure_area::start(
                secure_area::SecureAreaOptions {
                    root: root.clone(),
                    vault: vault.clone(),
                    cache,
                    policy_id,
                    company: bundle.as_ref().map(|b| b.company.clone()).unwrap_or_default(),
                    notice: bundle.as_ref().map(|b| b.notice.clone()).unwrap_or_default(),
                    classification: bundle
                        .as_ref()
                        .map(|b| b.classification.clone())
                        .unwrap_or_default(),
                    audit: None,
                },
                resolver,
            ) {
                Ok(area) => area,
                Err(e) => {
                    eprintln!("启动失败：{e}");
                    return 1;
                }
            };

            // 写入落盘加密：用户保存后 ProjFS 会落成实体明文，必须马上搬进密文库。
            // 用文件监控（去抖 1.5 s）而不是轮询，符合“变化驱动”的资源约定。
            let seal_area = std::sync::Arc::new(area);
            let seal_handle = watch::start(
                vec![root.clone()],
                std::time::Duration::from_millis(1500),
                {
                    let seal_area = std::sync::Arc::clone(&seal_area);
                    move |_path: std::path::PathBuf| {
                        seal_area.seal_dirty();
                    }
                },
            );
            let _seal_handle = match seal_handle {
                Ok(handle) => Some(handle),
                Err(e) => {
                    dhrust::warn!("安全区落盘加密监控未启动：{e}（保存后可能残留明文）");
                    None
                }
            };
            println!("安全区已启用：{}", root.display());
            println!("  密文库：{}", vault.display());
            println!("  在资源管理器打开该目录，看到的应是普通文件名（没有 .ogd）。");
            println!("按 Ctrl+C 停止。");
            runtime::STOP.store(false, std::sync::atomic::Ordering::SeqCst);
            while !runtime::STOP.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            0
        }
        Some("import") => {
            let Some(root) = root_arg else {
                eprintln!("用法：secure-area import --root <安全区> --file <源文件> [--as 相对路径] [--move]");
                return 2;
            };
            let Some(file) = arg_value(args, "--file") else {
                eprintln!("缺少 --file <源文件>");
                return 2;
            };
            let root = PathBuf::from(root);
            let source = PathBuf::from(&file);
            let state = state::load(base);
            if state.policy.is_none() {
                eprintln!("尚未同步策略（先执行 sync）");
                return 1;
            }
            let name = root
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| "secure".to_string());
            let vault = arg_value(args, "--vault")
                .map(PathBuf::from)
                .unwrap_or_else(|| base.join("Data").join("Vault").join(&name));
            let relative = arg_value(args, "--as").unwrap_or_else(|| {
                source
                    .file_name()
                    .map(|value| value.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unnamed".to_string())
            });
            let bundle = state.policy.clone();
            let policy_id = bundle
                .as_ref()
                .and_then(|b| b.policy_sets.first().map(|policy| policy.id.clone()))
                .unwrap_or_else(|| "default".to_string());
            let options = secure_area::SecureAreaOptions {
                root: root.clone(),
                vault: vault.clone(),
                cache: base.join("Data").join("VaultCache").join(&name),
                policy_id: policy_id.clone(),
                company: bundle.as_ref().map(|b| b.company.clone()).unwrap_or_default(),
                notice: bundle.as_ref().map(|b| b.notice.clone()).unwrap_or_default(),
                classification: bundle
                    .as_ref()
                    .map(|b| b.classification.clone())
                    .unwrap_or_default(),
                audit: None,
            };
            let key = match ops::policy_key(&state, &policy_id) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("取策略密钥失败：{e}");
                    return 1;
                }
            };
            let keep = !args.iter().any(|arg| arg == "--move");
            match secure_area::import_file(&options, &key, &source, &relative, keep) {
                Ok(vault_path) => {
                    println!("已导入：{} → {}", source.display(), vault_path.display());
                    println!(
                        "安全区 {} 里现在应该能直接看到 {}（重启 secure-area run 或刷新资源管理器）。",
                        root.display(),
                        relative
                    );
                    if keep {
                        println!("源文件保留；如确认无误可自行删除（或用 --move 让客户端删）。");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("导入失败：{e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("用法：secure-area [status|run|import] --root <目录> [--vault <密文库>]");
            eprintln!("  status 检查系统支持与目录是否可启用");
            eprintln!("  run    前台运行安全区（调试用；正式由客户端服务托管）");
            eprintln!("  import --file <源文件> [--as 相对路径] [--move]  把明文加密进密文库");
            2
        }
    }
}

/// 从 `--key value` 形式取参数。
fn arg_value(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|item| item == key)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

/// 列出当前的受控打开会话（明文只在受控临时目录，且会被自动回写）。
fn sessions_command(base: &Path) -> u8 {
    let sessions = opensession::load(base);
    if sessions.is_empty() {
        println!("当前无受控打开会话。");
        return 0;
    }
    println!("受控打开会话 {} 个：", sessions.len());
    for session in &sessions {
        println!(
            "  · [{}] {}\n      原文件：{}{}\n      打开于：{}；回写 {} 次",
            session.session_id,
            session.temp,
            session.container,
            if opensession::container_exists(session) {
                ""
            } else {
            "（原文件已不存在）"
            },
            chrono::DateTime::from_timestamp(session.opened_at, 0)
                .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "-".to_string()),
            session.writes
        );
    }
    println!("提示：{}", opensession::service_hint());
    0
}

// ————— 服务化 —————

fn install_command(base: &Path) -> u8 {
    match service::install(base, true) {
        Ok(()) => {
            println!("服务已安装并启动：{}", service::SERVICE_NAME);
            println!("已设置失败恢复策略（崩溃 5s/10s/30s 自动重启）。");
            // 双击 `.ogd` 即可受控打开（用户不需要知道“先解密”这一步）。
            match assoc::register(&std::env::current_exe().unwrap_or_default()) {
                Ok(()) => println!("已注册文件关联：双击 .ogd 直接打开（当前用户）。"),
                Err(e) => println!("文件关联注册失败（不影响保护）：{e}"),
            }
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
            if let Err(e) = assoc::unregister() {
                println!("解除文件关联失败（可手动清理）：{e}");
            }
            0
        }
        Err(e) => {
            eprintln!("卸载失败（需管理员权限）：{e}");
            1
        }
    }
}

/// 注册 / 解除 `.ogd` 文件关联（不需要管理员：写 HKCU）。
fn assoc_command(action: &str) -> u8 {
    match action {
        "register-assoc" => {
            let exe = match std::env::current_exe() {
                Ok(exe) => exe,
                Err(e) => {
                    eprintln!("取当前程序路径失败：{e}");
                    return 1;
                }
            };
            match assoc::register(&exe) {
                Ok(()) => {
                    println!("已注册 .ogd 关联：双击加密文件即由 OutGuard 受控打开。");
                    println!("当前命令：{}", assoc::query().unwrap_or_else(|| "-".into()));
                    0
                }
                Err(e) => {
                    eprintln!("注册失败：{e}");
                    1
                }
            }
        }
        "unregister-assoc" => match assoc::unregister() {
            Ok(()) => {
                println!("已解除 .ogd 关联。");
                0
            }
            Err(e) => {
                eprintln!("解除失败：{e}");
                1
            }
        },
        _ => 2,
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
