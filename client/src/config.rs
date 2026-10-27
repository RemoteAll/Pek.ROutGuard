//! 客户端配置：`Config/OutGuard.Client.toml`（`TomlConfig` 加载，保存时备份旧文件）。

use std::path::{Path, PathBuf};

use dhrust::config::TomlConfig;
use serde::{Deserialize, Serialize};

/// 首次运行写出的配置模板。
pub const TEMPLATE: &str = include_str!("../res/OutGuard.Client.toml.template");
/// 配置相对路径（相对程序基目录）。
pub const CONFIG_RELATIVE: &str = "Config/OutGuard.Client.toml";

/// 密码加密种子（**有意硬编码**：密钥不做配置项，避免随配置外泄）。
const SECRET_SEED: &str = "Pek.ROutGuard.Client/2026";

/// 客户端配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ClientConfig {
    /// `[Client]` 段
    pub client: ClientSection,
}

/// `[Client]` 段。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ClientSection {
    /// 服务端地址（含协议与端口，如 `http://10.0.0.5:5600`）
    pub server_url: String,
    /// 注册码（服务端要求准入时填写）
    pub enroll_code: String,
    /// 员工账号（账号模式）
    pub account: String,
    /// 员工密码（`enc:v1:` 密文；空 = 未设置）
    pub password: String,
    /// 受控临时目录（留空 = 系统临时目录下 OutGuard 子目录）
    pub temp_dir: String,
    /// 兜底监控根路径（服务端策略优先）
    pub watch_roots: Vec<String>,
    /// 审计事件上报间隔（秒）
    pub report_interval_secs: u64,
    /// 运行模式：`dry_run`（演练，默认）或 `live`（实盘）。
    ///
    /// **演练模式只判定与记日志，绝不加密、不删除、不替换任何文件**。
    /// 调试/试点阶段必须保持 `dry_run`；确认无误后用
    /// `pek-outguard-client mode live --confirm` 切换（写配置 + 记审计）。
    pub mode: String,
    /// 加密成功后原文件的回收保留天数（0 = 直接删除，不推荐）。
    ///
    /// 实盘模式下原文件不直接删，而是移到 `Data/Recovery/<日期>/`，保留期满再清理；
    /// 这样即使判定/加密出问题也能拿回原文件。
    pub recovery_keep_days: u32,
    /// 是否允许把「桌面/文档/下载/盘符根/系统目录」这类危险目录作为监控根。
    /// 默认 `false`：这些目录会被直接跳过并告警，避免误加密整个用户资料。
    pub allow_risky_roots: bool,
    /// 安全区（透明加密目录）：列表里的目录会被映射成「普通文件名」视图，
    /// 用户在里面直接打开/保存，磁盘上只存密文（ProjFS 实现）。
    ///
    /// 要求：目录已存在且为空（历史文件用 `secure-area import` 导入）。
    pub secure_areas: Vec<String>,
}

impl ClientSection {
    /// 是否演练模式（默认是：`mode` 为空或不是 `live` 都当演练）。
    pub fn is_dry_run(&self) -> bool {
        !self.mode.trim().eq_ignore_ascii_case("live")
    }
}

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:5600".to_string(),
            enroll_code: String::new(),
            account: String::new(),
            password: String::new(),
            temp_dir: String::new(),
            watch_roots: Vec::new(),
            report_interval_secs: 30,
            mode: "dry_run".to_string(),
            recovery_keep_days: 7,
            allow_risky_roots: false,
            secure_areas: Vec::new(),
        }
    }
}

/// 配置文件路径。
pub fn config_path(base: &Path) -> PathBuf {
    base.join(CONFIG_RELATIVE)
}

/// 加载配置（缺失生成模板、缺键补齐、损坏备份重建，由 `TomlConfig` 完成）。
pub fn load(base: &Path) -> TomlConfig<ClientConfig> {
    TomlConfig::load(config_path(base), TEMPLATE)
}

/// 保存配置（TOML 整份重写；旧文件备份为 `.bak`）。
pub fn save(base: &Path, config: &ClientConfig) -> Result<PathBuf, String> {
    let path = config_path(base);
    let text = toml::to_string_pretty(config)
        .map_err(|e| format!("配置序列化失败：{e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建配置目录失败：{e}"))?;
    }
    if path.is_file() {
        let _ = std::fs::copy(&path, path.with_extension("toml.bak"));
    }
    // 先写临时文件再原子替换（占用时有重试），避免写一半的配置。
    let temp = path.with_extension("toml.tmp");
    std::fs::write(&temp, text).map_err(|e| format!("写入临时配置失败：{e}"))?;
    dhrust::io::safe_replace_file(&temp, &path)
        .map_err(|e| format!("写入配置失败：{e}"))?;
    Ok(path)
}

/// 加密密码（`enc:v1:`；空串原样返回）。
pub fn encrypt_password(plain: &str) -> String {
    if plain.is_empty() {
        return String::new();
    }
    let key = dhrust::secret::key_from_seed(SECRET_SEED);
    dhrust::secret::encrypt(plain, &key).unwrap_or_default()
}

/// 解密密码（失败返回空串）。
pub fn decrypt_password(stored: &str) -> String {
    if stored.is_empty() {
        return String::new();
    }
    let key = dhrust::secret::key_from_seed(SECRET_SEED);
    dhrust::secret::decrypt(stored, &key).unwrap_or_default()
}

/// 受控临时目录（配置为空时使用系统临时目录）。
pub fn temp_dir(config: &ClientSection) -> PathBuf {
    let raw = config.temp_dir.trim();
    if raw.is_empty() {
        std::env::temp_dir().join("Pek").join("OutGuard")
    } else {
        PathBuf::from(raw)
    }
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
            "outguard-client-cfg-{}-{stamp}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    #[test]
    fn password_roundtrip_and_not_plaintext() {
        let stored = encrypt_password("s3cret-pass");
        assert!(stored.starts_with("enc:v1:"), "必须使用 enc:v1 格式");
        assert!(!stored.contains("s3cret"), "不得出现明文");
        assert_eq!(decrypt_password(&stored), "s3cret-pass");
        assert_eq!(decrypt_password(""), "");
        assert_eq!(encrypt_password(""), "");
    }

    #[test]
    fn save_and_reload() {
        let dir = temp_base("save");
        let mut config = ClientConfig::default();
        config.client.server_url = "http://10.0.0.5:5600".into();
        config.client.account = "zhangsan".into();
        config.client.password = encrypt_password("pass123");
        save(&dir, &config).expect("保存配置");

        let loaded = load(&dir);
        assert_eq!(loaded.value().client.server_url, "http://10.0.0.5:5600");
        assert_eq!(
            decrypt_password(&loaded.value().client.password),
            "pass123"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
