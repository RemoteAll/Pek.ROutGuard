//! 客户端 ↔ 服务端协议模型（serde 双端共用）。
//!
//! 传输：HTTPS + JSON；身份：每请求 Ed25519 签名（见 [`signature_payload`]）。
//! 原则：**心跳只发变化项**（未变化字段为 `None`，服务端保留旧值），避免周期性重复带宽。

use serde::{Deserialize, Serialize};

use crate::rules::PolicySet;

/// 协议版本（不兼容变更时递增）。
pub const PROTOCOL_VERSION: u32 = 1;

/// 终端状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientStatus {
    /// 已注册，等待管理员准入。
    Pending,
    /// 已准入，可拉取策略。
    Active,
    /// 被拒绝。
    Rejected,
    /// 被禁用（仍上报事件，但不给策略）。
    Disabled,
}

/// 注册请求（安装后首次启动自动调用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    /// 机器码（服务端以此识别重装/换机）。
    pub machine_id: String,
    /// 主机名。
    pub hostname: String,
    /// 操作系统描述（如 `Windows 11 23H2 x64`）。
    pub os: String,
    /// 客户端版本。
    pub client_version: String,
    /// 设备公钥（Ed25519，base64）。
    pub public_key: String,
    /// 注册码（服务端开启"注册码准入"时必填）。
    #[serde(default)]
    pub enroll_code: String,
}

/// 注册响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    /// 终端 ID（后续请求的 `X-OG-Client`）。
    pub client_id: String,
    /// 终端令牌（服务端可选二次校验；不作为唯一鉴权手段）。
    pub client_token: String,
    /// 状态。
    pub status: ClientStatus,
    /// 服务端时间（unix 秒；用于时钟偏移告警）。
    pub server_time: i64,
}

/// 客户端健康快照（心跳里只发变化项）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientHealth {
    /// 主服务是否运行。
    pub service_running: bool,
    /// 守护进程是否运行。
    pub guard_running: bool,
    /// 本地待上报事件数。
    pub pending_events: u32,
    /// 已离线天数（0 = 在线）。
    pub offline_days: u32,
}

/// 心跳请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest {
    /// 终端 ID。
    pub client_id: String,
    /// 客户端版本。
    pub client_version: String,
    /// 当前生效的策略版本。
    pub policy_version: u32,
    /// 主机名（变化才发）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// 当前登录用户（变化才发）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logged_user: Option<String>,
    /// 操作系统（变化才发）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// 健康快照（变化才发）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<ClientHealth>,
    /// 自上次心跳以来新增的异常计数（篡改/拒绝打开/卸载尝试）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anomalies: Option<u32>,
}

/// 服务端指令。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCommand {
    /// 立即拉取策略。
    SyncPolicy,
    /// 执行升级。
    Upgrade,
    /// 密钥轮换完成，重新拉取密钥。
    RotateKey,
    /// 卸载已获批准（带令牌）。
    UninstallApproved,
}

/// 心跳响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponse {
    /// 服务端时间（unix 秒）。
    pub server_time: i64,
    /// 期望的策略版本（与客户端不一致时客户端应拉取）。
    pub policy_version: u32,
    /// 指令列表。
    #[serde(default)]
    pub commands: Vec<ClientCommand>,
}

/// 服务端包裹后的策略密钥（base64；用终端公钥或 TLS 通道保护）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedPolicyKey {
    /// 规则集 ID。
    pub policy_id: String,
    /// 密钥版本。
    pub key_version: u32,
    /// 包裹后的密钥（base64）。
    pub wrapped_key: String,
}

/// 策略包（版本未变时服务端可返回 304 / 空包）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBundle {
    /// 策略总版本（多规则集合并后的单调版本）。
    pub version: u32,
    /// 规则集（已按绑定关系解析后的生效集合）。
    pub policy_sets: Vec<PolicySet>,
    /// 规则集密钥。
    pub wrapped_keys: Vec<WrappedPolicyKey>,
    /// 需要监控的根路径（客户端只监控这些，避免全盘劳作）。
    pub watch_roots: Vec<String>,
    /// 客户端必须排除的目录（受控临时目录、自身数据目录）。
    pub exclude_paths: Vec<String>,
    /// 容器扩展名（默认 `ogd`）。
    pub container_ext: String,
    /// 服务端时间（unix 秒）。
    pub server_time: i64,
}

/// 审计事件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// 文件被加密。
    Encrypt,
    /// 文件被解密（受控打开/外发）。
    Decrypt,
    /// 受控打开成功。
    Open,
    /// 拒绝打开（未授权/离线超期/策略禁止）。
    DenyOpen,
    /// 明文外带（复制/另存到非受控位置）。
    PlaintextExport,
    /// 尝试卸载。
    UninstallAttempt,
    /// 尝试停止服务。
    StopAttempt,
    /// 程序/配置被篡改。
    Tamper,
    /// 离线超期。
    Offline,
    /// 策略回执。
    PolicyAck,
    /// 外发申请。
    ApproveRequest,
    /// 客户端内部错误。
    Error,
}

impl EventType {
    /// 稳定的字符串形式（入库/检索）。
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::Encrypt => "encrypt",
            EventType::Decrypt => "decrypt",
            EventType::Open => "open",
            EventType::DenyOpen => "deny_open",
            EventType::PlaintextExport => "plaintext_export",
            EventType::UninstallAttempt => "uninstall_attempt",
            EventType::StopAttempt => "stop_attempt",
            EventType::Tamper => "tamper",
            EventType::Offline => "offline",
            EventType::PolicyAck => "policy_ack",
            EventType::ApproveRequest => "approve_request",
            EventType::Error => "error",
        }
    }
}

/// 单条审计事件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientEvent {
    /// 事件 ID（客户端生成；服务端以此去重）。
    pub event_id: String,
    /// 事件类型。
    pub event_type: EventType,
    /// 发生时间（unix 毫秒）。
    pub occurred_at: i64,
    /// 相关文件路径。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 命中的规则 ID。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// 终端登录用户。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// 相关进程名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// 文件大小（字节）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// 补充说明（已脱敏）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 事件批量上报请求（单批 ≤ 200 条）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsRequest {
    /// 事件列表。
    pub events: Vec<ClientEvent>,
}

/// 事件批量上报响应。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsResponse {
    /// 新接收条数。
    pub accepted: usize,
    /// 重复条数（已入库，幂等丢弃）。
    pub duplicated: usize,
    /// 被拒条数（格式非法/超限）。
    pub rejected: usize,
}

/// 外发申请。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    /// 申请的文件路径列表。
    pub files: Vec<String>,
    /// 申请原因。
    pub reason: String,
    /// 接收方（公司/人/邮箱）。
    pub receiver: String,
    /// 期望有效期（小时）。
    pub valid_hours: u32,
    /// 申请人。
    pub user: String,
}

/// 审批状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// 待审批。
    Pending,
    /// 已批准。
    Approved,
    /// 已拒绝。
    Rejected,
    /// 已过期。
    Expired,
    /// 已吊销。
    Revoked,
}

/// 升级包信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeInfo {
    /// 目标版本。
    pub version: String,
    /// 下载地址。
    pub url: String,
    /// SHA-256（十六进制）。
    pub sha256: String,
    /// 服务端签名（Ed25519，base64）。
    pub signature: String,
    /// 是否强制升级（旧版本不再被接受）。
    pub mandatory: bool,
}

/// 卸载令牌（服务端签发，客户端内置公钥验签）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallToken {
    /// 目标终端 ID。
    pub client_id: String,
    /// 目标机器码。
    pub machine_id: String,
    /// 一次性随机数。
    pub nonce: String,
    /// 过期时间（unix 秒）。
    pub expire_at: i64,
    /// 服务端签名（Ed25519，base64）。
    pub signature: String,
}

/// 请求签名载荷（规范化，服务端逐字节重建）。
///
/// `method` 大写；`path` 含查询串；`body` 为原始请求体（空体用空字节）。
pub fn signature_payload(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        timestamp,
        nonce,
        crate::crypto::hex(&crate::crypto::sha256(body))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Action;

    #[test]
    fn heartbeat_omits_unchanged_fields() {
        let request = HeartbeatRequest {
            client_id: "c1".into(),
            client_version: "0.1.0".into(),
            policy_version: 7,
            hostname: None,
            logged_user: None,
            os: None,
            health: None,
            anomalies: None,
        };
        let json = serde_json::to_string(&request).expect("序列化成功");
        assert!(!json.contains("hostname"), "未变化字段不应出现：{json}");
        assert!(json.contains("policyVersion"));
    }

    #[test]
    fn policy_bundle_roundtrip() {
        let bundle = PolicyBundle {
            version: 3,
            policy_sets: vec![PolicySet {
                id: "p1".into(),
                name: "研发".into(),
                version: 3,
                key_version: 1,
                default_action: Action::Plaintext,
                exclude_paths: vec!["D:\\Work\\temp".into()],
                rules: Vec::new(),
            }],
            wrapped_keys: vec![WrappedPolicyKey {
                policy_id: "p1".into(),
                key_version: 1,
                wrapped_key: "AAAA".into(),
            }],
            watch_roots: vec!["D:\\Work".into()],
            exclude_paths: vec!["C:\\ProgramData\\Pek\\OutGuard\\temp".into()],
            container_ext: "ogd".into(),
            server_time: 1_800_000_000,
        };

        let json = serde_json::to_string(&bundle).expect("序列化成功");
        let back: PolicyBundle = serde_json::from_str(&json).expect("反序列化成功");
        assert_eq!(back, bundle);
    }

    #[test]
    fn signature_payload_is_stable_and_differs_by_field() {
        let a = signature_payload("post", "/api/client/heartbeat", 100, "n1", b"{}");
        let b = signature_payload("POST", "/api/client/heartbeat", 100, "n1", b"{}");
        assert_eq!(a, b, "方法大小写不应影响载荷");

        let c = signature_payload("POST", "/api/client/heartbeat", 101, "n1", b"{}");
        assert_ne!(a, c, "时间戳参与签名");

        let d = signature_payload("POST", "/api/client/heartbeat", 100, "n2", b"{}");
        assert_ne!(a, d, "nonce 参与签名");

        let e = signature_payload("POST", "/api/client/heartbeat", 100, "n1", b"{\"a\":1}");
        assert_ne!(a, e, "body 摘要参与签名");
    }

    #[test]
    fn event_type_strings_are_stable() {
        assert_eq!(EventType::Encrypt.as_str(), "encrypt");
        assert_eq!(EventType::DenyOpen.as_str(), "deny_open");
        assert_eq!(EventType::PlaintextExport.as_str(), "plaintext_export");
    }
}
