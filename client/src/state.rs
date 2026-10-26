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
}
