//! Pek.ROutGuard Client —— 终端（库形态，供 bin 与测试共用）。
//!
//! 设计口径：
//! - **配置可改、保护不可停**：客户端提供配置入口（Server 地址 / 账号密码），但**不提供停止保护与卸载**；
//!   卸载需服务端签发的卸载令牌（M2）。
//! - **凭据不明文落盘**：账号密码用 `dhrust::secret`（AES-256-GCM，`enc:v1:`）加密后再写入配置。
//! - **策略只执行**：规则与策略密钥全部来自服务端；本地缓存放在 `Data/state.json`（0600）。

pub mod api;
pub mod assoc;
pub mod config;
pub mod driver;
pub mod opensession;
pub mod ops;
pub mod projfs;
pub mod runtime;
pub mod safety;
pub mod secure_area;
pub mod service;
pub mod state;
pub mod watch;

use std::path::PathBuf;

/// 程序基目录（`PEK_OUTGUARD_CLIENT_BASE` 环境变量可覆盖，便于测试与便携部署）。
pub fn base_dir() -> PathBuf {
    dhrust::io::base_dir(&["PEK_OUTGUARD_CLIENT_BASE"])
}

/// 版本号。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 产品名。
pub const PRODUCT: &str = "Pek.ROutGuard Client";
