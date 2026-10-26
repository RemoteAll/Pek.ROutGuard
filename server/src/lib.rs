//! Pek.ROutGuard Server —— 管理端（库形态，供 bin 与集成测试共用）。
//!
//! 职责：
//! - 终端注册与准入（机器码为唯一码，资产台账落库）
//! - 规则集管理 + 策略下发（版本化，终端回执）
//! - 密钥托管（MasterKey 落盘，PolicyKey 按需派生）
//! - 审计事件收集与查询
//! - Web 面板（登录 + 概览 + 终端 + 规则集 + 事件）

pub mod app;
pub mod client_api;
pub mod config;
pub mod db;
pub mod keys;
pub mod panel;

use std::path::PathBuf;

/// 程序基目录（`PEK_OUTGUARD_BASE` 环境变量可覆盖，便于便携部署与测试）。
pub fn base_dir() -> PathBuf {
    dhrust::io::base_dir(&["PEK_OUTGUARD_BASE"])
}

/// 版本号。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 产品名。
pub const PRODUCT: &str = "Pek.ROutGuard";

/// 服务名（服务化注册用）。
pub const SERVICE_NAME: &str = "PekROutGuard";
