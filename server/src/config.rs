//! `Config/OutGuard.toml`：服务端配置（`TomlConfig` 维护：缺失生成、缺键补齐、损坏重建）。

use std::path::{Path, PathBuf};

use dhrust::config::TomlConfig;
use serde::{Deserialize, Serialize};

/// 首次运行写出的配置模板（全字段中文说明）。
pub const TEMPLATE: &str = include_str!("../res/OutGuard.toml.template");

/// 配置相对路径（相对程序基目录）。
pub const CONFIG_RELATIVE: &str = "Config/OutGuard.toml";

/// 服务端配置。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct OutGuardConfig {
    /// `[Server]` 段
    pub server: ServerSection,
}

/// `[Server]` 段。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ServerSection {
    /// 监听地址
    pub host: String,
    /// 监听端口
    pub port: u16,
    /// 是否允许非回环来源
    pub allow_remote: bool,
    /// 面板用户名
    pub web_user_name: String,
    /// 面板密码哈希（`盐:哈希`）
    pub web_password_hash: String,
    /// 鉴权级别：None / LocalOnly / Full
    pub web_auth_level: String,
    /// 公司名称（写入容器明文头）
    pub company_name: String,
    /// 防泄密提示语
    pub notice: String,
    /// 默认密级
    pub classification: String,
    /// 是否自动批准终端注册
    pub auto_approve: bool,
    /// 默认监控根路径
    pub watch_roots: Vec<String>,
    /// 客户端必须排除的目录
    pub exclude_paths: Vec<String>,
    /// 离线宽限天数（0 = 不限制）
    pub offline_grace_days: u32,
    /// 是否允许客户端卸载（默认 false；需临时放开时由管理员改为 true，客户端下次同步生效）
    pub allow_uninstall: bool,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 5600,
            allow_remote: false,
            web_user_name: "admin".to_string(),
            web_password_hash: String::new(),
            web_auth_level: "LocalOnly".to_string(),
            company_name: "示例科技有限公司".to_string(),
            notice: "本文件已加密，仅限安装 OutGuard 客户端的授权电脑打开。如需外发请联系信息安全部门。"
                .to_string(),
            classification: "内部".to_string(),
            auto_approve: false,
            watch_roots: Vec::new(),
            exclude_paths: Vec::new(),
            offline_grace_days: 7,
            allow_uninstall: false,
        }
    }
}

/// 配置文件路径。
pub fn config_path(base: &Path) -> PathBuf {
    base.join(CONFIG_RELATIVE)
}

/// 加载配置（缺失生成模板、缺键补齐、损坏备份重建，均由 `TomlConfig` 完成）。
pub fn load(base: &Path) -> TomlConfig<OutGuardConfig> {
    TomlConfig::load(config_path(base), TEMPLATE)
}

/// 面板密码哈希：`盐:SHA-256(salt:password)`。
pub fn hash_password(salt: &str, password: &str) -> String {
    dhrust::sign::salted_sha256_hex(salt, password)
}

/// 校验面板密码。
pub fn verify_password(stored: &str, password: &str) -> bool {
    let Some((salt, expected)) = stored.split_once(':') else {
        return false;
    };
    let actual = hash_password(salt, password);
    // 常量时间比较，避免计时侧信道。
    constant_time_eq(actual.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let stored = format!("ab12cd34:{}", hash_password("ab12cd34", "s3cret"));
        assert!(verify_password(&stored, "s3cret"));
        assert!(!verify_password(&stored, "wrong"));
        assert!(!verify_password("bad-format", "s3cret"));
        assert!(!verify_password(&stored, ""));
    }
}
