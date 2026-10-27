//! 受控打开会话：让 `.ogd` 真的能当文件用（打开 → 编辑 → 保存 → 自动回写为密文）。
//!
//! **为什么需要这个模块**：受控打开原本只是"解密到临时目录再交给 Office"，
//! 用户改完一保存，改动只落在临时目录的明文上——加密文件里还是旧内容，
//! 用户等于白干；同时临时目录里的明文长期残留，反而是泄密风险。
//!
//! **这里的闭环**：
//! 1. 打开时解密到 `{临时目录}/{原名}.{会话ID}.{扩展名}`，并把会话登记到 `Data/sessions.json`；
//! 2. 常驻服务进程监听临时目录，文件改动去抖后**用原容器的策略密钥重新加密**，
//!    原子替换回 `.ogd`（保留原密级/创建者/规则），并记 `decrypt` 审计事件；
//! 3. 会话超时（[`SESSION_TTL_SECS`]）且近期无改动后清理明文。
//!
//! **为什么不删明文**：用户可能还在程序里开着；删掉会让"另存/撤销"失败。
//! 明文只活在受控临时目录，由超时清理兜底。

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use pek_outguard_core::container;
use serde::{Deserialize, Serialize};

use crate::state::ClientState;
use crate::{ops};

/// 会话登记文件（相对程序基目录）。
pub const SESSIONS_RELATIVE: &str = "Data/sessions.json";
/// 会话存活上限（秒）：超过且近期无改动即清理明文。
pub const SESSION_TTL_SECS: i64 = 2 * 3600;
/// 回写去抖（毫秒）：Office/WPS 保存会连续产生多个写事件。
pub const WRITEBACK_DEBOUNCE_MS: u64 = 3000;
/// 最近一次回写后多久内不清理（避免清理正在编辑的文件）。
const PURGE_GRACE_SECS: i64 = 600;

/// 一次受控打开会话。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenSession {
    /// 会话 ID（8 位 hex，拼进临时文件名便于识别）
    pub session_id: String,
    /// 临时明文绝对路径
    pub temp: String,
    /// 原加密容器绝对路径（回写目标）
    pub container: String,
    /// 打开时间（unix 秒）
    pub opened_at: i64,
    /// 最近一次成功回写时间（unix 秒；0 = 尚未回写）
    pub last_writeback: i64,
    /// 累计回写次数
    pub writes: u32,
    /// 最近一次回写时明文的 SHA-256（十六进制）
    ///
    /// 用途：Windows/Office 打开文件也会产生 Modify 事件（访问时间、临时锁文件），
    /// 靠哈希对比掉这种“假改动”，避免每次打开都白白重新加密一遍大文件。
    #[serde(default)]
    pub last_sha256: String,
}

/// 回写结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Writeback {
    /// 内容与上次回写一致，已跳过（不记审计，不刷日志）。
    Unchanged,
    /// 已写入，附明文大小与哈希。
    Written {
        /// 明文字节数
        size: u64,
        /// 明文 SHA-256（十六进制）
        sha256: String,
    },
}

/// 登记文件路径。
pub fn sessions_path(base: &Path) -> PathBuf {
    base.join(SESSIONS_RELATIVE)
}

/// 读取会话登记（损坏时当空表，不阻塞服务启动）。
pub fn load(base: &Path) -> Vec<OpenSession> {
    match std::fs::read_to_string(sessions_path(base)) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
            dhrust::warn!("受控打开登记解析失败（忽略并重建）：{e}");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

/// 保存会话登记。
pub fn save(base: &Path, sessions: &[OpenSession]) -> Result<(), String> {
    let path = sessions_path(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建数据目录失败：{e}"))?;
    }
    let text = serde_json::to_string_pretty(sessions)
        .map_err(|e| format!("会话登记序列化失败：{e}"))?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, text).map_err(|e| format!("写入会话登记失败：{e}"))?;
    std::fs::rename(&temp, &path).map_err(|e| format!("替换会话登记失败：{e}"))?;
    Ok(())
}

/// 登记文件修改时间（服务进程靠它做"变化才重载"，不做周期全量解析）。
pub fn mtime(base: &Path) -> Option<SystemTime> {
    std::fs::metadata(sessions_path(base))
        .and_then(|meta| meta.modified())
        .ok()
}

/// 生成受控临时文件名：`合同.a1b2c3d4.docx`（会话 ID 嵌在扩展名前，便于识别与清理）。
pub fn temp_path(temp_dir: &Path, original_name: &str, session_id: &str) -> PathBuf {
    let source = Path::new(original_name);
    let stem = source
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unnamed".to_string());
    let stem = dhrust::io::sanitize_file_name(&stem);
    match source.extension() {
        Some(ext) if !ext.is_empty() => {
            temp_dir.join(format!("{stem}.{session_id}.{}", ext.to_string_lossy()))
        }
        _ => temp_dir.join(format!("{stem}.{session_id}")),
    }
}

/// 转绝对路径：会话登记必须用绝对路径，否则常驻服务（cwd 不同）回写时会找不到文件。
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// 受控打开：解密到受控临时目录 → 登记会话 → 交给默认程序。
pub fn open(
    base: &Path,
    state: &ClientState,
    temp_dir: &Path,
    container_path: &Path,
) -> Result<OpenSession, String> {
    let container_path = &absolute(container_path);
    if !container_path.is_file() {
        return Err(format!("文件不存在：{}", container_path.display()));
    }
    let temp_dir = &absolute(temp_dir);
    std::fs::create_dir_all(temp_dir)
        .map_err(|e| format!("创建受控临时目录失败（{}）：{e}", temp_dir.display()))?;

    let header = {
        let mut reader = std::io::BufReader::new(
            std::fs::File::open(container_path)
                .map_err(|e| format!("打开容器失败（{}）：{e}", container_path.display()))?,
        );
        container::read_header(&mut reader).map_err(|e| format!("读取容器头失败：{e}"))?
    };

    let session_id = dhrust::random::hex(4);
    let temp = temp_path(temp_dir, &header.original_name, &session_id);
    ops::decrypt_to_file(state, container_path, &temp)?;

    let session = OpenSession {
        session_id,
        temp: temp.to_string_lossy().to_string(),
        container: container_path.to_string_lossy().to_string(),
        opened_at: chrono::Utc::now().timestamp(),
        last_writeback: 0,
        writes: 0,
        last_sha256: String::new(),
    };

    // 先登记再打开：程序可能立刻写入，晚登记会漏掉第一波改动。
    let mut sessions = load(base);
    sessions.retain(|item| item.temp != session.temp);
    sessions.push(session.clone());
    save(base, &sessions)?;

    if let Err(e) = ops::launch_with_default_app(&temp) {
        // 不撤销会话：明文已落地，用户可手动双击那个文件；登记还在，回写照旧。
        dhrust::warn!(
            "受控打开：启动默认程序失败（{}），明文已解密到临时目录：{e}",
            temp.display()
        );
    }
    dhrust::info!(
        "受控打开：{} → {}（会话 {}）",
        container_path.display(),
        temp.display(),
        session.session_id
    );
    Ok(session)
}

/// 把临时明文回写为加密容器（保留原头信息）。
///
/// 内容未变（哈希一致）时返回 [`Writeback::Unchanged`]，不产生任何写入与审计——
/// 这样“打开文件”本身触发的 Modify 事件不会变成一次白白的重新加密。
pub fn writeback(state: &ClientState, session: &OpenSession) -> Result<Writeback, String> {
    let plain = std::fs::read(&session.temp)
        .map_err(|e| format!("读取临时明文失败（{}）：{e}", session.temp))?;
    let sha256 = pek_outguard_core::crypto::hex(&pek_outguard_core::crypto::sha256(&plain));
    if !session.last_sha256.is_empty() && session.last_sha256 == sha256 {
        return Ok(Writeback::Unchanged);
    }
    let size = ops::reseal_container(
        state,
        Path::new(&session.temp),
        Path::new(&session.container),
    )?;
    Ok(Writeback::Written { size, sha256 })
}

/// 找出与给定路径匹配的会话（大小写不敏感，Windows 路径不区分大小写）。
pub fn match_session<'a>(sessions: &'a [OpenSession], changed: &Path) -> Option<&'a OpenSession> {
    let changed = changed.to_string_lossy().to_ascii_lowercase();
    sessions
        .iter()
        .find(|item| item.temp.to_ascii_lowercase() == changed)
}

/// 是否该跳过（回写产生的临时文件、容器自身等）。
pub fn should_skip(path: &Path) -> bool {
    let text = path.to_string_lossy().to_ascii_lowercase();
    text.ends_with(".tmp") || text.ends_with(".ogd")
}

/// 清理超期会话：删除明文并从登记移除，返回被清理的数量。
///
/// 口径：`opened_at` 超过 [`SESSION_TTL_SECS`]，且距最后一次回写超过
/// [`PURGE_GRACE_SECS`]（避免清理用户正在编辑的文件）。
pub fn purge_expired(base: &Path, now: i64) -> usize {
    let sessions = load(base);
    if sessions.is_empty() {
        return 0;
    }
    let mut kept = Vec::with_capacity(sessions.len());
    let mut purged = 0;
    for session in sessions {
        let idle_since = if session.last_writeback > 0 {
            session.last_writeback
        } else {
            session.opened_at
        };
        let expired =
            now - session.opened_at > SESSION_TTL_SECS && now - idle_since > PURGE_GRACE_SECS;
        if !expired {
            kept.push(session);
            continue;
        }
        match std::fs::remove_file(&session.temp) {
            Ok(()) => {
                purged += 1;
                dhrust::info!("清理受控临时明文（会话 {}）：{}", session.session_id, session.temp);
            }
            // 文件已被用户/程序清掉也算清理完成；其它错误保留登记下轮再试。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                purged += 1;
            }
            Err(e) => {
                dhrust::warn!(
                    "清理受控临时明文失败（会话 {}，{}）：{e}",
                    session.session_id,
                    session.temp
                );
                kept.push(session);
            }
        }
    }
    if purged > 0 && let Err(e) = save(base, &kept) {
        dhrust::warn!("保存受控打开登记失败：{e}");
    }
    purged
}

/// 会话中对应的原文件是否还存在（用于提示"已删除的容器"）。
pub fn container_exists(session: &OpenSession) -> bool {
    Path::new(&session.container).is_file()
}

/// 读取会话对应的原容器明文头（展示用）。
pub fn read_container_header(session: &OpenSession) -> Option<container::Header> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(&session.container).ok()?);
    container::read_header(&mut reader).ok()
}

/// 会话登记与本地状态无关的辅助：判断服务是否在跑（回写依赖常驻服务）。
pub fn service_hint() -> &'static str {
    "编辑保存后由常驻服务自动加密回写；服务未运行时改动只留在临时明文里"
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use pek_outguard_core::crypto;
    use pek_outguard_core::protocol::{PolicyBundle, WrappedPolicyKey};
    use pek_outguard_core::rules::PolicySet;

    fn temp_base(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // 有意不用系统 TEMP：内置规则会软排除临时目录（判定为放行，无法加密）。
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace")
            .join("target")
            .join("client-test-sessions");
        let dir = root.join(format!("{}-{stamp}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    fn state_with_policy(token: &str) -> ClientState {
        let policy = PolicySet::builtin_default();
        let master = [9u8; crypto::KEY_LEN];
        let key = crypto::derive_policy_key(&master, &policy.id, policy.key_version).expect("派生");
        let packed = crypto::wrap_for_client(token, &key).expect("包裹");
        ClientState {
            client_id: "c-1".into(),
            client_token: token.into(),
            status: "active".into(),
            policy: Some(PolicyBundle {
                version: policy.version,
                policy_sets: vec![policy],
                wrapped_keys: vec![WrappedPolicyKey {
                    policy_id: "default".into(),
                    key_version: 1,
                    wrapped_key: base64::engine::general_purpose::STANDARD.encode(packed),
                }],
                watch_roots: Vec::new(),
                exclude_paths: Vec::new(),
                container_ext: "ogd".into(),
                company: "示例科技有限公司".into(),
                notice: "本文件已加密".into(),
                classification: "内部".into(),
                allow_uninstall: false,
                offline_grace_days: 0,
                server_time: 0,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn temp_name_keeps_stem_and_strips_dangerous_chars() {
        let dir = PathBuf::from("C:/temp");
        let path = temp_path(&dir, "../合同:2026.docx", "a1b2c3d4");
        let name = path.file_name().expect("有文件名").to_string_lossy().to_string();
        assert!(name.contains("a1b2c3d4"), "{name}");
        assert!(name.ends_with(".docx"), "{name}");
        assert!(!name.contains(".."), "{name}");
        assert!(!name.contains(':'), "{name}");
    }

    #[test]
    fn register_writeback_and_purge_cycle() {
        let base = temp_base("cycle");
        let temp_dir = base.join("temp");
        std::fs::create_dir_all(&temp_dir).expect("建临时目录");
        let state = state_with_policy("0011223344556677");

        // 先造一个真实的加密容器
        let source = base.join("合同.docx");
        std::fs::write(&source, b"v1").expect("写原文件");
        let container = ops::encrypt_file(&state, &source, &crate::ops::EncryptOptions::live(base.join("recovery"))).expect("加密").output;

        // 受控打开（只解密 + 登记，不在此处真正启动 Office）
        let header = {
            let mut reader = std::io::BufReader::new(
                std::fs::File::open(&container).expect("开容器"),
            );
            container::read_header(&mut reader).expect("读头")
        };
        let temp = temp_path(&temp_dir, &header.original_name, "a1b2c3d4");
        ops::decrypt_to_file(&state, &container, &temp).expect("解密到受控目录");
        let session = OpenSession {
            session_id: "a1b2c3d4".into(),
            temp: temp.to_string_lossy().to_string(),
            container: container.to_string_lossy().to_string(),
            opened_at: chrono::Utc::now().timestamp(),
            last_writeback: 0,
            writes: 0,
            last_sha256: String::new(),
        };
        save(&base, std::slice::from_ref(&session)).expect("登记");
        assert!(Path::new(&session.temp).is_file());
        assert_eq!(load(&base).len(), 1);

        // 用户编辑并保存 → 回写
        std::fs::write(&session.temp, b"v2 after edit").expect("编辑保存");
        let outcome = writeback(&state, &session).expect("回写");
        let sha = match outcome {
            Writeback::Written { size, sha256 } => {
                assert_eq!(size, b"v2 after edit".len() as u64);
                sha256
            }
            Writeback::Unchanged => panic!("首次回写不应判定为未变"),
        };

        // 内容没再变 → 不重复加密（避免“打开动作”变成一次无意义的重加密）
        let refreshed = OpenSession {
            last_sha256: sha,
            ..session.clone()
        };
        assert_eq!(
            writeback(&state, &refreshed).expect("二次回写"),
            Writeback::Unchanged
        );

        // 回写后容器里应能解出编辑后的内容（说明改动真的落回加密文件）
        let out_dir = base.join("out");
        let plain = ops::decrypt_file(&state, &container, &out_dir).expect("解密验证");
        assert_eq!(std::fs::read(&plain).expect("读明文"), b"v2 after edit");

        // 未超期不清理
        let now = chrono::Utc::now().timestamp();
        assert_eq!(purge_expired(&base, now), 0);

        // 超期后清理明文并移除登记
        let later = now + SESSION_TTL_SECS + PURGE_GRACE_SECS + 1;
        assert_eq!(purge_expired(&base, later), 1);
        assert!(load(&base).is_empty());
        assert!(!Path::new(&session.temp).exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn match_session_ignores_path_case() {
        let session = OpenSession {
            session_id: "aa".into(),
            temp: "C:\\Temp\\合同.a1.docx".into(),
            container: "D:\\Work\\合同.docx.ogd".into(),
            opened_at: 0,
            last_writeback: 0,
            writes: 0,
            last_sha256: String::new(),
        };
        let sessions = vec![session];
        assert!(match_session(&sessions, Path::new("c:\\temp\\合同.a1.docx")).is_some());
        assert!(match_session(&sessions, Path::new("C:\\Temp\\别的.docx")).is_none());
    }

    #[test]
    fn purge_keeps_recently_written_session() {
        let base = temp_base("grace");
        let temp = base.join("x.a1.docx");
        std::fs::write(&temp, b"x").expect("写文件");
        let now = chrono::Utc::now().timestamp();
        save(
            &base,
            &[OpenSession {
                session_id: "a1".into(),
                temp: temp.to_string_lossy().to_string(),
                container: base.join("x.docx.ogd").to_string_lossy().to_string(),
                opened_at: now - SESSION_TTL_SECS - 100,
                // 刚回写过 → 处在保护期内，不能被清理
                last_writeback: now - 60,
                writes: 3,
                last_sha256: String::new(),
            }],
        )
        .expect("保存");
        assert_eq!(purge_expired(&base, now), 0);
        assert!(temp.exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
