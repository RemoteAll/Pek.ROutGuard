//! 客户端运行时：注册 → 同步策略 → 监控自动加密 → 心跳 / 事件上报。
//!
//! 周期口径（资源约定）：主循环 30 s（事件上报每轮、心跳每 60 s），
//! 监控只盯策略下发的 `watch_roots`，去抖 800 ms，无周期全盘扫描。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pek_outguard_core::machine;
use pek_outguard_core::protocol::{
    ClientEvent, EventType, EventsRequest, HeartbeatRequest, RegisterRequest,
};
use pek_outguard_core::rules::Action;
use pek_outguard_core::signature::DeviceKey;

use crate::api::Api;
use crate::config::{self, ClientSection};
use crate::driver;
use crate::state::{self, ClientState};
use crate::watch::{self, WatchHandle};
use crate::{VERSION, opensession, ops, safety, secure_area};

/// 停止标志（服务 Stop/Shutdown 或 Ctrl+C 置位）。
pub static STOP: AtomicBool = AtomicBool::new(false);
/// 主循环周期。
const TICK: Duration = Duration::from_secs(30);
/// 文件变化去抖。
const DEBOUNCE: Duration = Duration::from_millis(800);
/// 本地事件队列上限（超出丢弃最旧，防磁盘/内存膨胀）。
const MAX_PENDING_EVENTS: usize = 5000;
/// 恢复在线时要记日志的最小离线时长（1 分钟）：低于此值视为网络抶动，不刷日志。
const ONLINE_RESUME_LOG_SECS: i64 = 60;

/// 请求停止运行循环。
pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

/// 运行客户端（前台或服务模式共用）。
///
/// **离线优先（硬要求）**：服务端不可达时**绝不退出**，用 `Data/state.json` 里缓存的
/// 策略与密钥继续保护——该加密的照常加密（不丢用户数据），离线期间的审计事件留在本地队列；
/// 一旦恢复连接，主循环自动补注册 / 补同步 / 补传事件。
/// 只有「解密 / 受控打开」在**超过服务端下发的离线宽限期**后拒绝（防止拔网线永久离线绕过吊销）。
pub fn run(base: &Path) -> Result<(), String> {
    STOP.store(false, Ordering::SeqCst);
    let section = config::load(base).value().client.clone();
    let api = Api::new(&section.server_url)?;
    let mut initial = state::load(base);

    // 在线准备是非致命步骤：失败即进入离线模式，不影响后续监控与加密。
    if let Err(e) = prepare_online(base, &section, &api, &mut initial) {
        let cached = initial.policy.is_some();
        dhrust::warn!(
            "离线启动：{e}\n  本地策略缓存：{}；{}",
            if cached {
                format!("有（version={}）", initial.policy_version)
            } else {
                "无".to_string()
            },
            if cached {
                "已用缓存策略继续保护，联网后自动同步"
            } else {
                "尚无缓存策略：联网同步后自动启用加密"
            }
        );
    }

    let shared = Arc::new(Mutex::new(initial));
    let options = run_options(base, &section);
    let mut watcher = start_watch(base, Arc::clone(&shared), &options)?;
    let mut current_roots = roots_of(&watcher);

    // 受控打开回写：监听受控临时目录，用户保存明文后自动重新加密回 `.ogd`。
    // 这是“打开→编辑→保存”闭环的关键：没有它，用户的修改只落在临时明文上。
    let temp_dir = config::temp_dir(&section);
    let _session_watch = start_session_watch(base, &temp_dir, Arc::clone(&shared));

    // 安全区（透明加密目录）：虚拟根里用户看到普通文件名，磁盘上只存密文。
    let _secure_areas = start_secure_areas(base, &section, Arc::clone(&shared));

    let mut tick: u32 = 0;
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(TICK);
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        tick += 1;

        // ① 事件上报：失败保留本地队列（离线期间的审计不丢，联网后按 200 条/批补传）。
        if let Err(e) = flush_events(&api, &shared) {
            dhrust::warn!("事件上报失败（已保留本地队列，联网后补传）：{e}");
        }

        // ② 心跳（每 60 s）：兼任「在线探测」与「策略版本比对」。
        if tick.is_multiple_of(2) {
            match heartbeat(&api, &shared) {
                Ok(remote_version) => {
                    mark_online(base, &shared);
                    let (local_version, has_policy) = {
                        let state = shared.lock().map_err(|_| "状态锁不可用".to_string())?;
                        (state.policy_version, state.policy.is_some())
                    };
                    // 密钥健康检查：终端令牌换发（重装/重新注册）后旧包裹会失效，
                    // 不主动重同步的话，所有文件都会“打不开”——必须能自己恢复。
                    let key_broken = has_policy && !policy_key_usable(&shared);
                    if remote_version != local_version || !has_policy || key_broken {
                        if key_broken {
                            dhrust::warn!(
                                "本地策略密钥不可用（终端令牌可能已换发），强制重新同步…"
                            );
                        }
                        dhrust::info!("策略需要同步：本地 v{local_version} → 服务端 v{remote_version}");
                        if let Err(e) = sync_policy_from_shared(base, &api, &shared) {
                            dhrust::warn!("策略同步失败（继续用本地缓存）：{e}");
                        }
                    }
                }
                Err(e) => dhrust::warn!("心跳失败（离线运行，下轮自动重试）：{e}"),
            }

            // 首次安装时断网（尚未注册）：每轮重试注册，联网后立即补齐身份与策略。
            retry_register_if_needed(base, &section, &api, &shared);
        }

        // ③ 让文件监控与「当前生效策略的 WatchRoots」保持一致：
        //    覆盖「离线补同步后才有根」与「策略取消监控根」两种转换（只在变化时重建）。
        if let Err(e) = reconcile_watch(base, &shared, &mut watcher, &mut current_roots, &options) {
            dhrust::warn!("重建文件监控失败（下轮重试）：{e}");
        }

        // ④ 离线超期检查（纯内存计算，无 IO）。
        check_offline(&shared);

        // ⑤ 受控打开会话清理（每 10 分钟一次，而非每轮；纯本地文件操作）。
        if tick.is_multiple_of(20) {
            let purged = opensession::purge_expired(base, chrono::Utc::now().timestamp());
            if purged > 0 {
                dhrust::info!("已清理 {purged} 个受控打开的临时明文");
            }
            let removed = safety::purge_recovery(base, section.recovery_keep_days);
            if removed > 0 {
                dhrust::info!(
                    "已清理 {removed} 个过期回收区目录（保留 {} 天）",
                    section.recovery_keep_days
                );
            }
        }
    }

    drop(watcher);
    dhrust::info!("客户端运行循环已退出");
    Ok(())
}

/// 让监控与「策略要求的根」对齐：变化（含无→有、有→无）才重建，否则零动作。
fn reconcile_watch(
    base: &Path,
    shared: &Arc<Mutex<ClientState>>,
    watcher: &mut Option<WatchHandle>,
    current_roots: &mut Vec<String>,
    options: &RunOptions,
) -> Result<(), String> {
    let candidates: Vec<String> = {
        let Ok(state) = shared.lock() else {
            return Ok(());
        };
        state
            .policy
            .as_ref()
            .map(|bundle| bundle.watch_roots.clone())
            .unwrap_or_default()
    };
    // 与 `start_watch` 同口径（含危险目录过滤），避免反复重建。
    let desired: Vec<String> = safety::filter_roots(&candidates, options.allow_risky_roots).0;
    if desired == *current_roots {
        return Ok(());
    }
    dhrust::info!("监控根变化：{:?} → {desired:?}", *current_roots);
    *watcher = start_watch(base, Arc::clone(shared), options)?;
    *current_roots = roots_of(watcher);
    Ok(())
}

/// 运行时安全选项（启动时从配置快照，改配置需重启服务生效）。
struct RunOptions {
    /// 加密选项（演练 / 回收区）
    encrypt: ops::EncryptOptions,
    /// 是否允许危险监控根
    allow_risky_roots: bool,
}

/// 根据配置构造运行选项，并把当前模式显式打印到日志（运维一眼能看出会不会动文件）。
fn run_options(base: &Path, section: &ClientSection) -> RunOptions {
    let options = if section.is_dry_run() {
        dhrust::warn!(
            "运行模式：演练（dry_run）—— 只判定并记日志，**不会加密、不会移动、不会删除任何文件**；\
             确认无误后用 `pek-outguard-client mode live --confirm` 切换"
        );
        RunOptions {
            encrypt: ops::EncryptOptions::default(),
            allow_risky_roots: section.allow_risky_roots,
        }
    } else {
        let recovery = safety::recovery_dir(base);
        dhrust::warn!(
            "运行模式：实盘（live）—— 受控目录内的文件会被加密，原文件移入回收区 {}（保留 {} 天）",
            recovery.display(),
            section.recovery_keep_days
        );
        RunOptions {
            encrypt: ops::EncryptOptions::live(recovery),
            allow_risky_roots: section.allow_risky_roots,
        }
    };
    if section.allow_risky_roots {
        dhrust::warn!("已允许危险监控根（AllowRiskyRoots = true）：桌面/文档/盘符根也可能被加密");
    }
    options
}

/// 在线准备：注册（如需）+ 同步策略。失败即视为离线，由调用方降级处理。
fn prepare_online(
    base: &Path,
    section: &ClientSection,
    api: &Api,
    state: &mut ClientState,
) -> Result<(), String> {
    if state.client_id.is_empty() {
        register(base, section, api, state)?;
    }
    sync_policy(base, api, state)?;
    Ok(())
}

/// 标记「刚刚与服务器通信成功」；顺带清零离线告警标记。
///
/// 落盘节流：事件队列短时每 60 s 落一次（state.json 只有几 KB）；
/// 队列较长（离线堆积）时跳过，等事件补传完再落，避免每分钟写上百 KB。
fn mark_online(base: &Path, shared: &Arc<Mutex<ClientState>>) {
    let Ok(mut state) = shared.lock() else {
        return;
    };
    let now = chrono::Utc::now().timestamp();
    // 只在“离线 → 在线”状态变化时记一笔（不每次心跳刷日志）。
    if state.last_online > 0 {
        let gap = (now - state.last_online).max(0);
        if gap > ONLINE_RESUME_LOG_SECS {
            dhrust::info!(
                "网络已恢复：与服务器通信成功（已离线 {} 分钟），开始补同步与补传事件",
                gap / 60
            );
        }
    }
    state.last_online = now;
    state.offline_reported = false;
    if state.pending_events.len() <= 200
        && let Err(e) = state::save(base, &state)
    {
        dhrust::warn!("在线状态落盘失败（不影响运行）：{e}");
    }
}

/// 本地缓存的策略密钥是否还能解开（纯内存，微秒级）。
///
/// 解不开的典型原因：终端重装/重新注册换发了令牌，而 `wrapped_key` 是用**旧令牌**包裹的。
fn policy_key_usable(shared: &Arc<Mutex<ClientState>>) -> bool {
    let Ok(state) = shared.lock() else {
        return true;
    };
    let Some(policy) = state
        .policy
        .as_ref()
        .and_then(|bundle| bundle.policy_sets.first())
    else {
        return true;
    };
    ops::policy_key(&state, &policy.id).is_ok()
}

/// 未注册时的重试（首次安装即断网的场景）。成功后立刻补同步策略。
fn retry_register_if_needed(
    base: &Path,
    section: &ClientSection,
    api: &Api,
    shared: &Arc<Mutex<ClientState>>,
) {
    let mut snapshot = {
        let Ok(state) = shared.lock() else {
            return;
        };
        if !state.client_id.is_empty() {
            return;
        }
        state.clone()
    };
    match register(base, section, api, &mut snapshot) {
        Ok(()) => {
            if let Ok(mut state) = shared.lock() {
                *state = snapshot;
            }
            dhrust::info!("终端注册成功（联网已恢复），立即同步策略");
            match sync_policy_from_shared(base, api, shared) {
                Ok(_) => {
                    mark_online(base, shared);
                }
                Err(e) => dhrust::warn!("注册成功但策略同步失败（下轮重试）：{e}"),
            }
        }
        Err(e) => dhrust::warn!("终端注册重试失败（保持离线，规则继续用本地缓存）：{e}"),
    }
}

/// 离线超期检查：首次超期时上报一条审计事件（避免每轮重复）。
fn check_offline(shared: &Arc<Mutex<ClientState>>) {
    let now = chrono::Utc::now().timestamp();
    let (exceeded, reported, days, grace) = {
        let Ok(state) = shared.lock() else {
            return;
        };
        (
            state.offline_exceeded(now),
            state.offline_reported,
            state.offline_days(now),
            state.offline_grace_days(),
        )
    };
    if !exceeded || reported {
        return;
    }
    dhrust::warn!(
        "离线超期：已离线 {days} 天 > 宽限 {grace} 天，解密/受控打开已拒绝（自动加密继续，用户数据不丢）"
    );
    push_event(
        shared,
        ClientEvent {
            event_id: dhrust::random::hex(8),
            event_type: EventType::Offline,
            occurred_at: chrono::Utc::now().timestamp_millis(),
            path: None,
            rule_id: None,
            user: Some(dhrust::sys::machine::user_name()),
            process_name: None,
            size: None,
            detail: Some(format!("离线 {days} 天，宽限 {grace} 天")),
        },
    );
    if let Ok(mut state) = shared.lock() {
        state.offline_reported = true;
    }
}

/// 设备种子（hex）→ Ed25519 密钥。
pub fn seed_key(seed_hex: &str) -> Result<DeviceKey, String> {
    Ok(DeviceKey::from_seed(&decode_seed(seed_hex)?))
}

/// 64 位 hex → 32 字节种子。
pub fn decode_seed(hex_text: &str) -> Result<[u8; 32], String> {
    let text = hex_text.trim();
    if text.len() != 64 {
        return Err(format!("设备种子长度非法：{}（期望 64 位 hex）", text.len()));
    }
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = hex_val(bytes[index * 2])?;
        let low = hex_val(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("设备种子含非法字符：{}", other as char)),
    }
}

fn now_text() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 注册终端（设备模式 + 账号模式字段）。
fn register(
    base: &Path,
    section: &ClientSection,
    api: &Api,
    state: &mut ClientState,
) -> Result<(), String> {
    let seed = state::ensure_device_seed(state);
    let device = seed_key(&seed)?;
    let guid = dhrust::sys::machine::machine_guid().unwrap_or_default();
    let host = dhrust::sys::machine::hostname();
    let cpu = dhrust::sys::machine::cpu_model().unwrap_or_default();
    let machine_id =
        machine::machine_id(&guid, &host, &cpu).unwrap_or_else(|_| dhrust::random::hex(16));
    let memory_mb = dhrust::sys::machine::memory_info()
        .map(|(total, _)| total / (1024 * 1024))
        .unwrap_or(0);

    let request = RegisterRequest {
        machine_id,
        hostname: host,
        os: dhrust::sys::machine::os_description(),
        client_version: VERSION.to_string(),
        public_key: device.public_key_b64(),
        enroll_code: section.enroll_code.clone(),
        hardware: Some(pek_outguard_core::protocol::HardwareInfo {
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

    let response = api.register(&request)?;
    state.client_id = response.client_id;
    state.client_token = response.client_token;
    state.status = format!("{:?}", response.status).to_lowercase();
    state::save(base, state)?;
    dhrust::info!("终端注册：clientId={} 状态={}", state.client_id, state.status);
    Ok(())
}

/// 同步策略；返回监控根列表。
fn sync_policy(
    base: &Path,
    api: &Api,
    state: &mut ClientState,
) -> Result<Vec<String>, String> {
    if state.client_id.is_empty() {
        return Err("终端未注册".into());
    }
    let bundle = api.policy(&state.client_id, &state.client_token)?;
    let roots = bundle.watch_roots.clone();
    state.policy_version = bundle.version;
    state.policy = Some(bundle);
    state.last_sync = now_text();
    state.status = "active".into();
    // 同步成功即证明在线：刷新离线基准，解除离线告警。
    state.last_online = chrono::Utc::now().timestamp();
    state.offline_reported = false;
    state::save(base, state)?;
    // 同步后立即验证密钥可用（令牌换发后旧包裹失效，必须当场发现，不能等用户打不开文件）。
    if let Some(policy) = state
        .policy
        .as_ref()
        .and_then(|bundle| bundle.policy_sets.first())
        && let Err(e) = ops::policy_key(state, &policy.id)
    {
        dhrust::warn!(
            "新下发的策略密钥无法解包（policy={}）：{e}；\
             若终端曾重装/重新注册，请重启客户端让它重新注册",
            policy.id
        );
    }
    dhrust::info!(
        "策略已同步：version={} 监控根={}",
        state.policy_version,
        roots.len()
    );
    // 同步成功后把规则与密钥推给内核驱动。
    // **失败不影响策略同步**：驱动没装/没加载是开发与灰度期的正常状态。
    match push_to_driver(state) {
        Ok(note) => dhrust::info!("{note}"),
        Err(e) => dhrust::debug!("驱动未接入（{e}）；用户态加密流程照常工作"),
    }
    Ok(roots)
}

/// 把当前策略的受控路径/扩展名与 XTS 密钥推送给内核驱动。
///
/// 安全要点：
/// - 密钥由 `ops::policy_key` + `crypto::derive_xts_key` 现场派生，**只经 IOCTL 走内存**，
///   不落盘、不进日志；
/// - 驱动没加载 / 权限不足时返回 Err，调用方只记日志，绝不中断正常流程。
fn push_to_driver(state: &ClientState) -> Result<String, String> {
    use pek_outguard_core::{crypto, rules::Action};

    let bundle = state.policy.as_ref().ok_or("策略未同步")?;
    let client = driver::DriverClient::open()?;

    // ① 受控路径：watch_roots 换算成内核看到的 NT 路径
    let mut prefixes = Vec::new();
    for root in &bundle.watch_roots {
        match driver::dos_to_nt_path(Path::new(root)) {
            Ok(nt) => prefixes.push(nt),
            Err(e) => dhrust::warn!("监控根 {root} 无法换算成 NT 路径，驱动侧跳过：{e}"),
        }
    }

    // ② 扩展名：只取"加密"动作且指定了扩展名的规则，去重后交给驱动
    let mut exts: Vec<String> = Vec::new();
    for set in &bundle.policy_sets {
        for rule in &set.rules {
            if rule.action != Action::Encrypt {
                continue;
            }
            for ext in &rule.extensions {
                let normalized = if ext.starts_with('.') {
                    ext.to_lowercase()
                } else {
                    format!(".{}", ext.to_lowercase())
                };
                if normalized != ".*" && !exts.contains(&normalized) {
                    exts.push(normalized);
                }
            }
        }
    }

    if prefixes.is_empty() && exts.is_empty() {
        return Err("策略里没有可下发的受控路径或扩展名".into());
    }

    let rules = driver::DriverRules::new(bundle.version.max(1), &prefixes, &exts)?;
    client.set_rules(&rules)?;

    // ③ 密钥：从策略密钥派生 XTS 密钥（与应用层加密同一把，保证透明加密能解开已加密文件）
    let mut key_note = "密钥未下发（策略缺少规则集）".to_string();
    if let Some(set) = bundle.policy_sets.first()
        && let Ok(policy_key) = ops::policy_key(state, &set.id)
    {
        let xts = crypto::derive_xts_key(&policy_key);
        let request = driver::KeyRequest::new(set.key_version.max(1), &xts)?;
        match client.set_policy_key(&request) {
            Ok(()) => key_note = format!("密钥已下发（版本 {}）", set.key_version.max(1)),
            Err(e) => key_note = format!("密钥下发失败：{e}"),
        }
    }

    Ok(format!(
        "已推送驱动：{} 条路径、{} 个扩展名；{key_note}",
        rules.path_prefix_count, rules.ext_count
    ))
}

fn sync_policy_from_shared(
    base: &Path,
    api: &Api,
    shared: &Arc<Mutex<ClientState>>,
) -> Result<Vec<String>, String> {
    let mut snapshot = shared
        .lock()
        .map_err(|_| "状态锁不可用".to_string())?
        .clone();
    let roots = sync_policy(base, api, &mut snapshot)?;
    *shared.lock().map_err(|_| "状态锁不可用".to_string())? = snapshot;
    Ok(roots)
}

fn heartbeat(api: &Api, shared: &Arc<Mutex<ClientState>>) -> Result<u32, String> {
    let (client_id, token, version) = {
        let state = shared.lock().map_err(|_| "状态锁不可用".to_string())?;
        (
            state.client_id.clone(),
            state.client_token.clone(),
            state.policy_version,
        )
    };
    let request = HeartbeatRequest {
        client_id: client_id.clone(),
        client_version: VERSION.to_string(),
        policy_version: version,
        hostname: None,
        logged_user: Some(dhrust::sys::machine::user_name()),
        os: None,
        health: None,
        anomalies: None,
        ip: None,
        mac: None,
        hardware: None,
    };
    let response = api.heartbeat(&client_id, &token, &request)?;
    if let Ok(mut state) = shared.lock() {
        state.last_heartbeat = now_text();
    }
    Ok(response.policy_version)
}

fn flush_events(api: &Api, shared: &Arc<Mutex<ClientState>>) -> Result<(), String> {
    let (client_id, token, batch) = {
        let state = shared.lock().map_err(|_| "状态锁不可用".to_string())?;
        if state.pending_events.is_empty() {
            return Ok(());
        }
        let batch: Vec<ClientEvent> = state.pending_events.iter().take(200).cloned().collect();
        (
            state.client_id.clone(),
            state.client_token.clone(),
            batch,
        )
    };
    api.events(
        &client_id,
        &token,
        &EventsRequest {
            events: batch.clone(),
        },
    )?;
    if let Ok(mut state) = shared.lock() {
        state.pending_events.drain(..batch.len());
    }
    Ok(())
}

fn roots_of(handle: &Option<WatchHandle>) -> Vec<String> {
    handle
        .as_ref()
        .map(|handle| {
            handle
                .roots
                .iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn start_watch(
    base: &Path,
    shared: Arc<Mutex<ClientState>>,
    options: &RunOptions,
) -> Result<Option<WatchHandle>, String> {
    let candidates: Vec<String> = {
        let state = shared.lock().map_err(|_| "状态锁不可用".to_string())?;
        state
            .policy
            .as_ref()
            .map(|bundle| bundle.watch_roots.clone())
            .unwrap_or_default()
    };
    // 安全阀：危险目录（盘符根/桌面/文档/下载/用户目录本身）默认拒绝。
    let (kept, rejected) = safety::filter_roots(&candidates, options.allow_risky_roots);
    for (path, reason) in &rejected {
        dhrust::warn!(
            "跳过危险的监控根 {path}：{reason}（如确需监控请在客户端配置 AllowRiskyRoots = true）"
        );
    }
    let roots: Vec<PathBuf> = kept.into_iter().map(PathBuf::from).collect();
    if roots.is_empty() {
        dhrust::warn!("无可用监控根：自动加密未启用（需在服务端配置 WatchRoots 为安全区目录）");
        return Ok(None);
    }

    let base = base.to_path_buf();
    let handler_shared = Arc::clone(&shared);
    let encrypt = options.encrypt.clone();
    let handle = watch::start(roots, DEBOUNCE, move |path| {
        handle_change(&base, &handler_shared, &path, &encrypt);
    })?;
    Ok(Some(handle))
}

/// 启动配置里的全部安全区（透明加密目录）。返回句柄，drop 即全部停止。
fn start_secure_areas(
    base: &Path,
    section: &ClientSection,
    shared: Arc<Mutex<ClientState>>,
) -> Vec<(Arc<secure_area::SecureArea>, Option<WatchHandle>)> {
    let mut running = Vec::new();
    if section.secure_areas.is_empty() {
        return running;
    }
    if !crate::projfs::is_supported() {
        dhrust::warn!(
            "配置了安全区但系统不支持 ProjFS（需 Windows 10 1809+ / Server 2019+），已跳过"
        );
        return running;
    }

    for root_text in &section.secure_areas {
        let root_text = root_text.trim();
        if root_text.is_empty() {
            continue;
        }
        let root = PathBuf::from(root_text);
        // 安全阀：危险目录不允许当安全区（和监控根同一套判定）。
        if !section.allow_risky_roots
            && let Some(reason) = safety::risky_root_reason(&root)
        {
            dhrust::warn!("跳过危险的安全区 {root_text}：{reason}");
            continue;
        }
        if !root.is_dir() {
            dhrust::warn!("安全区目录不存在（请先创建）：{root_text}");
            continue;
        }

        let name = root
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "secure".to_string());
        let bundle = shared.lock().ok().and_then(|state| state.policy.clone());
        let (Some(bundle), Ok(key)) = (
            bundle,
            shared
                .lock()
                .ok()
                .and_then(|state| {
                    let policy_id = state
                        .policy
                        .as_ref()
                        .and_then(|b| b.policy_sets.first().map(|p| p.id.clone()))
                        .unwrap_or_else(|| "default".to_string());
                    ops::policy_key(&state, &policy_id).ok()
                })
                .ok_or("策略密钥不可用"),
        ) else {
            dhrust::warn!("安全区 {root_text} 未启用：策略尚未就绪（联网同步后重启服务生效）");
            continue;
        };

        let options = secure_area::SecureAreaOptions {
            root: root.clone(),
            vault: base.join("Data").join("Vault").join(&name),
            cache: base.join("Data").join("VaultCache").join(&name),
            policy_id: bundle
                .policy_sets
                .first()
                .map(|policy| policy.id.clone())
                .unwrap_or_else(|| "default".to_string()),
            company: bundle.company.clone(),
            notice: bundle.notice.clone(),
            classification: bundle.classification.clone(),
            audit: Some(Arc::new({
                let shared = Arc::clone(&shared);
                let root_name = name.clone();
                move |action: &'static str, relative: &str, size: Option<u64>| {
                    let event_type = match action {
                        // 保存回写与导入都属于"文件被加密落盘"。
                        "seal" | "import" => EventType::Encrypt,
                        _ => EventType::Open,
                    };
                    let detail = format!("安全区 {root_name}：{action}");
                    let path = format!("{}\\{relative}", root_name);
                    let event = ClientEvent {
                        event_id: dhrust::random::hex(8),
                        event_type,
                        occurred_at: chrono::Utc::now().timestamp_millis(),
                        path: Some(path),
                        rule_id: None,
                        user: Some(dhrust::sys::machine::user_name()),
                        process_name: None,
                        size,
                        detail: Some(detail),
                    };
                    push_event(&shared, event);
                }
            })),
        };

        // 目录里若有残留明文（上次异常退出/用户手工拷入），先吸收进密文库。
        if let Err(e) = secure_area::absorb_existing(&options, &key) {
            dhrust::warn!("安全区 {root_text} 残留清理失败：{e}");
        }

        let area = match secure_area::start(options, {
            let shared = Arc::clone(&shared);
            Arc::new(move |policy_id: &str| {
                shared
                    .lock()
                    .ok()
                    .and_then(|state| ops::policy_key(&state, policy_id).ok())
            })
        }) {
            Ok(area) => Arc::new(area),
            Err(e) => {
                dhrust::warn!("安全区 {root_text} 启动失败：{e}");
                continue;
            }
        };

        // 保存后落盘加密：ProjFS 会先落成实体明文，这里立刻搬进密文库。
        let seal_watch = attach_seal_watch(&area, &root);

        dhrust::info!("安全区已就绪（透明加密）：{root_text}");
        running.push((area, seal_watch));
    }
    running
}

/// 给安全区挂上“保存即加密”的文件监控（**命令行与服务共用，不要再各写一份**）。
///
/// 只处理发生变化的那一个文件，不做全盘扫描——大目录下保存也不会卡。
pub fn attach_seal_watch(
    area: &Arc<secure_area::SecureArea>,
    root: &Path,
) -> Option<WatchHandle> {
    spawn_dehydrate_worker(area);
    let seal_area = Arc::clone(area);
    let root_for_watch = root.to_path_buf();
    match watch::start(
        vec![root.to_path_buf()],
        Duration::from_millis(1500),
        move |path: PathBuf| {
            // ProjFS 自己也会有噪音事件（hydrate/占位符状态），seal_path 内部会过滤。
            if !path.starts_with(&root_for_watch) {
                return;
            }
            seal_area.seal_path(&path);
        },
    ) {
        Ok(handle) => Some(handle),
        Err(e) => {
            dhrust::warn!(
                "安全区 {} 落盘加密监控未启动：{e}（保存后可能残留明文，可用 secure-area run 重启）",
                root.display()
            );
            None
        }
    }
}

/// 空闲脱水：打开过的文件在 `DEHYDRATE_IDLE` 内没再被读，就降级回占位符。
///
/// 这是“读完之后磁盘上不留明文”的收口——ProjFS 会把解密结果落在本地，
/// 不脱水就等于把明文留在磁盘上。**只遍历内存表，不扫目录**，开销可忽略。
pub fn spawn_dehydrate_worker(area: &Arc<secure_area::SecureArea>) {
    let weak = Arc::downgrade(area);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(DEHYDRATE_TICK);
            let Some(area) = weak.upgrade() else {
                return; // 安全区关闭，线程退出
            };
            let count = area.dehydrate_idle(DEHYDRATE_IDLE);
            if count > 0 {
                dhrust::info!("空闲脱水完成：{count} 个文件已恢复为占位符（磁盘上不再留明文）");
            }
        }
    });
}

/// 空闲脱水的巡检周期（内存比对，不读盘）。
const DEHYDRATE_TICK: Duration = Duration::from_secs(5);
/// 文件多久没被读就把明文从磁盘上收回（用户还在用时不会被抽走）。
const DEHYDRATE_IDLE: Duration = Duration::from_secs(60);

/// 启动受控打开回写监控：临时目录内的明文改动 → 重新加密回 `.ogd`。
fn start_session_watch(
    base: &Path,
    temp_dir: &Path,
    shared: Arc<Mutex<ClientState>>,
) -> Option<WatchHandle> {
    if let Err(e) = std::fs::create_dir_all(temp_dir) {
        dhrust::warn!(
            "创建受控临时目录失败（{}）：{e}（受控打开回写不可用）",
            temp_dir.display()
        );
        return None;
    }
    let base = base.to_path_buf();
    match watch::start(
        vec![temp_dir.to_path_buf()],
        Duration::from_millis(opensession::WRITEBACK_DEBOUNCE_MS),
        move |path| handle_session_change(&base, &shared, &path),
    ) {
        Ok(handle) => Some(handle),
        Err(e) => {
            dhrust::warn!(
                "受控打开回写监控未启动（{}）：{e}（编辑后无法自动回写）",
                temp_dir.display()
            );
            None
        }
    }
}

/// 受控临时文件的改动处理：命中会话 → 重新加密回原容器 → 更新登记 + 审计。
fn handle_session_change(base: &Path, shared: &Arc<Mutex<ClientState>>, path: &Path) {
    if opensession::should_skip(path) || !path.is_file() {
        return;
    }
    let sessions = opensession::load(base);
    let Some(session) = opensession::match_session(&sessions, path).cloned() else {
        // 不是受控打开会话（用户自己放进该目录的其它文件），不处理。
        return;
    };

    let snapshot = match shared.lock() {
        Ok(state) => state.clone(),
        Err(_) => return,
    };
    match opensession::writeback(&snapshot, &session) {
        Ok(opensession::Writeback::Unchanged) => {
            // 打开文件本身也会触发 Modify（访问时间/锁文件），内容没变就不做事。
            dhrust::debug!("受控打开内容未变，跳过回写（会话 {}）", session.session_id);
        }
        Ok(opensession::Writeback::Written { size, sha256 }) => {
            let now = chrono::Utc::now().timestamp();
            let mut updated = opensession::load(base);
            if let Some(item) = updated
                .iter_mut()
                .find(|item| item.session_id == session.session_id)
            {
                item.writes += 1;
                item.last_writeback = now;
                item.last_sha256 = sha256;
            }
            if let Err(e) = opensession::save(base, &updated) {
                dhrust::warn!("保存受控打开登记失败：{e}");
            }
            dhrust::info!(
                "受控打开回写完成（会话 {}）：{} → {}（{size} 字节）",
                session.session_id,
                session.temp,
                session.container
            );
            push_event(
                shared,
                ClientEvent {
                    event_id: dhrust::random::hex(8),
                    event_type: EventType::Decrypt,
                    occurred_at: chrono::Utc::now().timestamp_millis(),
                    path: Some(session.container.clone()),
                    rule_id: None,
                    user: Some(dhrust::sys::machine::user_name()),
                    process_name: None,
                    size: Some(size),
                    detail: Some("受控打开编辑后回写（明文仅在受控临时目录）".to_string()),
                },
            );
        }
        Err(e) => dhrust::warn!(
            "受控打开回写失败（会话 {}，{}）：{e}",
            session.session_id,
            session.container
        ),
    }
}

/// 单个文件变化：规则判定 → 自动加密 → 事件入队。
fn handle_change(
    base: &Path,
    shared: &Arc<Mutex<ClientState>>,
    path: &Path,
    options: &ops::EncryptOptions,
) {
    if watch::should_skip(path) {
        return;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if !meta.is_file() {
        return;
    }

    let snapshot = match shared.lock() {
        Ok(state) => state.clone(),
        Err(_) => return,
    };
    let Some(bundle) = snapshot.policy.as_ref() else {
        return;
    };
    if bundle
        .exclude_paths
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return;
    }

    let judgement = match ops::judge(&snapshot, path, meta.len(), None) {
        Ok(judgement) => judgement,
        Err(_) => return,
    };
    if judgement.decision.action != Action::Encrypt {
        return;
    }

    match ops::encrypt_file(&snapshot, path, options) {
        // 演练模式：记录"将会加密"，磁盘上什么都没变，也不产生审计事件。
        Ok(outcome) if !outcome.applied => {
            dhrust::info!(
                "演练：命中规则 {}，将会加密 {}（未改动任何文件）",
                outcome.rule_id,
                path.display()
            );
        }
        Ok(outcome) => {
            dhrust::info!(
                "自动加密：{} → {}（规则 {}，原文件已移入回收区）",
                path.display(),
                outcome.output.display(),
                outcome.rule_id
            );
            push_event(
                shared,
                ClientEvent {
                    event_id: dhrust::random::hex(8),
                    event_type: EventType::Encrypt,
                    occurred_at: chrono::Utc::now().timestamp_millis(),
                    path: Some(path.to_string_lossy().to_string()),
                    rule_id: Some(outcome.rule_id),
                    user: Some(dhrust::sys::machine::user_name()),
                    process_name: None,
                    size: Some(outcome.plain_size),
                    detail: Some(format!("policy={}", outcome.policy_id)),
                },
            );
            if let Ok(state) = shared.lock() {
                // 这里保存的是“待上报事件队列”。保存失败 = 加密事件可能丢失 = 审计不完整，
                // 必须告警，绝不能静默忽略。
                if let Err(e) = state::save(base, &state) {
                    dhrust::warn!(
                        "自动加密事件已产生但状态保存失败（{}）：{e}；该事件可能在重启后丢失",
                        base.display()
                    );
                }
            }
        }
        Err(e) => dhrust::warn!("自动加密失败（{}）：{e}", path.display()),
    }
}

fn push_event(shared: &Arc<Mutex<ClientState>>, event: ClientEvent) {
    if let Ok(mut state) = shared.lock() {
        state.pending_events.push(event);
        if state.pending_events.len() > MAX_PENDING_EVENTS {
            let overflow = state.pending_events.len() - MAX_PENDING_EVENTS;
            state.pending_events.drain(..overflow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_decoding() {
        let key = seed_key(&"ab".repeat(32)).expect("解码");
        assert_eq!(key.public_key_b64().len(), 44);
        assert!(seed_key("zz").is_err());
    }
}
