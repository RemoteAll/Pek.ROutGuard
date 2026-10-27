//! 本地状态：终端身份、令牌、设备种子、策略缓存、待上报事件。
//!
//! 存放 `Data/state.json`（Unix 0600）。**策略密钥以包裹态缓存**（需配合令牌解包），
//! 令牌与状态同文件 → M2 迁移到 Windows DPAPI / Linux 机器密钥加密。

use std::path::{Path, PathBuf};

use pek_outguard_core::protocol::{ClientEvent, PolicyBundle};
use serde::{Deserialize, Serialize};

/// 状态文件（相对程序基目录）。
pub const STATE_RELATIVE: &str = "Data/state.json";

/// 客户端本地状态。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ClientState {
    /// 终端 ID（服务端下发）
    pub client_id: String,
    /// 终端令牌（服务端下发；用于策略密钥解包与接口鉴权）
    pub client_token: String,
    /// 服务端认定的状态：pending / active / rejected / disabled
    pub status: String,
    /// 设备私钥种子（Ed25519，hex；M2 用于请求签名）
    pub device_seed: String,
    /// 已生效策略版本
    pub policy_version: u32,
    /// 策略包缓存
    pub policy: Option<PolicyBundle>,
    /// 最近同步时间
    pub last_sync: String,
    /// 最近心跳时间
    pub last_heartbeat: String,
    /// 待上报事件
    pub pending_events: Vec<ClientEvent>,
    /// 最近一次与服务端通信成功的时间（unix 秒；离线判定的基准）
    pub last_online: i64,
    /// 是否已上报过“离线超期”事件（避免每轮重复上报）
    pub offline_reported: bool,
}

impl ClientState {
    /// 离线秒数（从未通信过返回 0：那时还没策略，本就无法解密）。
    pub fn offline_secs(&self, now: i64) -> i64 {
        if self.last_online <= 0 {
            0
        } else {
            (now - self.last_online).max(0)
        }
    }

    /// 离线天数（向上取整，便于展示“离线 3 天”）。
    pub fn offline_days(&self, now: i64) -> u32 {
        let secs = self.offline_secs(now);
        if secs <= 0 {
            0
        } else {
            ((secs + 86_399) / 86_400) as u32
        }
    }

    /// 服务端下发的离线宽限天数（`0` / 未同步 = 不限制）。
    pub fn offline_grace_days(&self) -> u32 {
        self.policy
            .as_ref()
            .map(|bundle| bundle.offline_grace_days)
            .unwrap_or(0)
    }

    /// 是否已超过离线宽限（超过后拒绝解密/受控打开，仍继续加密）。
    pub fn offline_exceeded(&self, now: i64) -> bool {
        let grace = self.offline_grace_days();
        grace > 0 && self.offline_secs(now) > i64::from(grace) * 86_400
    }

    /// 离线超期时给用户看的具体原因（用于拒绝提示与审计）。
    pub fn offline_block_reason(&self, now: i64) -> Option<String> {
        if !self.offline_exceeded(now) {
            return None;
        }
        Some(format!(
            "终端已离线 {} 天，超过 {} 天宽限期：为防绕过吊销与审计，已拒绝解密（请接入内网后重试；加密仍正常进行）",
            self.offline_days(now),
            self.offline_grace_days()
        ))
    }
}

/// 状态文件路径。
pub fn state_path(base: &Path) -> PathBuf {
    base.join(STATE_RELATIVE)
}

/// 读取状态（损坏时返回默认值，不阻塞客户端启动）。
pub fn load(base: &Path) -> ClientState {
    match std::fs::read_to_string(state_path(base)) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(state) => state,
            Err(e) => {
                dhrust::warn!("本地状态解析失败（将重新注册）：{e}");
                ClientState::default()
            }
        },
        Err(_) => ClientState::default(),
    }
}

/// 保存状态（Unix 0600）。
pub fn save(base: &Path, state: &ClientState) -> Result<(), String> {
    let path = state_path(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建数据目录失败：{e}"))?;
    }
    let text = serde_json::to_string_pretty(state).map_err(|e| format!("状态序列化失败：{e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("写入状态失败：{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// 取或生成设备种子（hex）。
pub fn ensure_device_seed(state: &mut ClientState) -> String {
    if state.device_seed.trim().is_empty() {
        state.device_seed = dhrust::random::hex(32);
    }
    state.device_seed.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "outguard-client-state-{}-{stamp}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    #[test]
    fn save_and_reload_state() {
        let dir = temp_base("roundtrip");
        let mut state = ClientState {
            client_id: "c-1".into(),
            client_token: "token".into(),
            status: "active".into(),
            ..Default::default()
        };
        let seed = ensure_device_seed(&mut state);
        assert_eq!(seed.len(), 64);

        save(&dir, &state).expect("保存");
        let loaded = load(&dir);
        assert_eq!(loaded.client_id, "c-1");
        assert_eq!(loaded.device_seed, seed);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_state_falls_back() {
        let dir = temp_base("corrupt");
        std::fs::create_dir_all(dir.join("Data")).expect("建目录");
        std::fs::write(state_path(&dir), "{not json").expect("写坏文件");
        let loaded = load(&dir);
        assert!(loaded.client_id.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn bundle_with_grace(days: u32) -> PolicyBundle {
        PolicyBundle {
            version: 1,
            policy_sets: Vec::new(),
            wrapped_keys: Vec::new(),
            watch_roots: Vec::new(),
            exclude_paths: Vec::new(),
            container_ext: "ogd".into(),
            company: "示例".into(),
            notice: "内部资料".into(),
            classification: "内部".into(),
            allow_uninstall: false,
            offline_grace_days: days,
            server_time: 0,
        }
    }

    #[test]
    fn offline_grace_blocks_only_after_exceeding() {
        let start = 1_700_000_000i64;
        let mut state = ClientState {
            last_online: start,
            policy: Some(bundle_with_grace(7)),
            ..Default::default()
        };

        // 当天：在线，不超期。
        assert_eq!(state.offline_days(start), 0);
        assert!(!state.offline_exceeded(start));
        assert!(state.offline_block_reason(start).is_none());

        // 离线 3 天多：仍不超期，宽限剩 4 天。
        let three_days = start + 3 * 86_400 + 60;
        assert_eq!(state.offline_days(three_days), 4);
        assert!(!state.offline_exceeded(three_days));

        // 刚好 7 天：边界内（未超过），仍允许解密。
        assert!(!state.offline_exceeded(start + 7 * 86_400));

        // 超过 7 天：拒绝解密，且原因里带天数与宽限。
        let nine_days = start + 9 * 86_400;
        assert!(state.offline_exceeded(nine_days));
        let reason = state.offline_block_reason(nine_days).expect("应给出原因");
        assert!(reason.contains("离线 9 天"), "{reason}");
        assert!(reason.contains("7 天宽限期"), "{reason}");
        assert!(reason.contains("加密仍正常进行"), "{reason}");

        // 恢复在线（刷新 last_online）后立刻解除。
        state.last_online = nine_days;
        assert!(!state.offline_exceeded(nine_days));
    }

    #[test]
    fn offline_grace_zero_means_unlimited() {
        let start = 1_700_000_000i64;
        let unlimited = ClientState {
            last_online: start,
            policy: Some(bundle_with_grace(0)),
            ..Default::default()
        };
        assert!(!unlimited.offline_exceeded(start + 365 * 86_400));

        // 未同步过策略（从未通信）：同样不限制（此时本就无密钥可解）。
        let fresh = ClientState::default();
        assert_eq!(fresh.offline_grace_days(), 0);
        assert!(!fresh.offline_exceeded(i64::MAX / 2));
    }
}
