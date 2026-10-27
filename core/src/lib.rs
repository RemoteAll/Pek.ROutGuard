//! Pek.ROutGuard 共享核心。
//!
//! 本 crate 是 **Server 与 Client 共用的唯一实现**，目的：同一份规则判定与容器格式，
//! 避免"服务端预览的判定结果"与"客户端实际执行"漂移。
//!
//! 模块：
//! - [`container`]：`OGD1` 加密容器（明文头 + AES-256-GCM 分块 + KeyBlock + SHA-256 尾部）
//! - [`crypto`]：HKDF-SHA256 策略密钥派生、DEK 包裹/拆包、分块 nonce
//! - [`rules`]：规则引擎（扩展名/文件名/路径/进程/大小 + 优先级 + 默认动作）
//! - [`protocol`]：客户端 ↔ 服务端协议模型（注册/心跳/策略/事件）
//! - [`signature`]：设备 Ed25519 密钥与请求签名
//! - [`error`]：统一错误类型
//!
//! 安全边界见 `docs/架构设计.md`：用户态方案不对抗本地管理员 + 内核工具/重装系统。

pub mod container;
pub mod crypto;
pub mod error;
pub mod machine;
pub mod meta;
pub mod protocol;
pub mod rules;
pub mod signature;
pub mod xts;

pub use error::{Error, Result};

/// 容器文件默认扩展名（可由策略覆盖；本值只用于"识别是否为本产品容器"的兜底）。
pub const CONTAINER_EXT: &str = "ogd";

/// 产品版本（构建期注入）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 产品名（写入容器头与审计）。
pub const PRODUCT: &str = "Pek.ROutGuard";

