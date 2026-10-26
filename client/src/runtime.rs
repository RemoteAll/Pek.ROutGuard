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
use crate::state::{self, ClientState};
use crate::watch::{self, WatchHandle};
use crate::{VERSION, ops};

/// 停止标志（服务 Stop/Shutdown 或 Ctrl+C 置位）。
pub static STOP: AtomicBool = AtomicBool::new(false);
/// 主循环周期。
const TICK: Duration = Duration::from_secs(30);
/// 文件变化去抖。
const DEBOUNCE: Duration = Duration::from_millis(800);
/// 本地事件队列上限（超出丢弃最旧，防磁盘/内存膨胀）。
const MAX_PENDING_EVENTS: usize = 5000;

/// 请求停止运行循环。
pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

/// 运行客户端（前台或服务模式共用）。
pub fn run(base: &Path) -> Result<(), String> {
    STOP.store(false, Ordering::SeqCst);
    let section = config::load(base).value().client.clone();
    let api = Api::new(&section.server_url)?;
    let mut initial = state::load(base);

    if initial.client_id.is_empty() {
        register(base, &section, &api, &mut initial)?;
    }
    if let Err(e) = sync_policy(base, &api, &mut initial) {
        dhrust::warn!("首次策略同步失败（将使用本地缓存）：{e}");
    }

    let shared = Arc::new(Mutex::new(initial));
    let mut watcher = start_watch(base, Arc::clone(&shared))?;
    let mut current_roots = roots_of(&watcher);

    let mut tick: u32 = 0;
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(TICK);
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        tick += 1;

        if let Err(e) = flush_events(&api, &shared) {
            dhrust::warn!("事件上报失败（保留本地队列）：{e}");
        }

        if tick.is_multiple_of(2) {
            match heartbeat(&api, &shared) {
                Ok(remote_version) => {
                    let local = shared.lock().map(|state| state.policy_version).unwrap_or(0);
                    if remote_version != local {
                        dhrust::info!("策略版本变化：{local} → {remote_version}");
                        match sync_policy_from_shared(base, &api, &shared) {
                            Ok(new_roots) if new_roots != current_roots => {
                                dhrust::info!("监控根变化，重启文件监控");
                                watcher = start_watch(base, Arc::clone(&shared))?;
                                current_roots = roots_of(&watcher);
                            }
                            Ok(_) => {}
                            Err(e) => dhrust::warn!("策略同步失败：{e}"),
                        }
                    }
                }
                Err(e) => dhrust::warn!("心跳失败：{e}"),
            }
        }
    }

    drop(watcher);
    dhrust::info!("客户端运行循环已退出");
    Ok(())
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
    state::save(base, state)?;
    dhrust::info!(
        "策略已同步：version={} 监控根={}",
        state.policy_version,
        roots.len()
    );
    Ok(roots)
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
) -> Result<Option<WatchHandle>, String> {
    let roots: Vec<PathBuf> = {
        let state = shared.lock().map_err(|_| "状态锁不可用".to_string())?;
        state
            .policy
            .as_ref()
            .map(|bundle| bundle.watch_roots.clone())
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .filter(|path| path.is_dir())
            .collect()
    };
    if roots.is_empty() {
        dhrust::warn!("策略未配置有效的 WatchRoots：自动加密未启用（配置后可重启服务）");
        return Ok(None);
    }

    let base = base.to_path_buf();
    let handler_shared = Arc::clone(&shared);
    let handle = watch::start(roots, DEBOUNCE, move |path| {
        handle_change(&base, &handler_shared, &path);
    })?;
    Ok(Some(handle))
}

/// 单个文件变化：规则判定 → 自动加密 → 事件入队。
fn handle_change(base: &Path, shared: &Arc<Mutex<ClientState>>, path: &Path) {
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

    match ops::encrypt_file(&snapshot, path) {
        Ok(outcome) => {
            dhrust::info!(
                "自动加密：{} → {}（规则 {}）",
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
                let _ = state::save(base, &state);
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
