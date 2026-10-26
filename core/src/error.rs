//! 统一错误类型。
//!
//! 库层不依赖任何具体 IO 实现（server/client 各自决定 io 语义），只做分类，
//! 便于调用方按类别决定"重试 / 上报 / 拒绝"。

use std::fmt;

/// 核心库错误。
#[derive(Debug)]
pub enum Error {
    /// 本地 IO 失败（读写文件、管道、网络流）。
    Io(std::io::Error),
    /// 容器格式不合法（魔数/版本/长度/完整性校验失败）。
    Format(String),
    /// 加密/解密失败（换钥、篡改、AAD 不匹配）。
    Crypto(String),
    /// 规则集或匹配条件不合法。
    Rule(String),
    /// 协议模型不合法（字段缺失、签名载荷等）。
    Protocol(String),
    /// 签名/验签失败。
    Signature(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO 错误：{e}"),
            Error::Format(msg) => write!(f, "容器格式错误：{msg}"),
            Error::Crypto(msg) => write!(f, "加密错误：{msg}"),
            Error::Rule(msg) => write!(f, "规则错误：{msg}"),
            Error::Protocol(msg) => write!(f, "协议错误：{msg}"),
            Error::Signature(msg) => write!(f, "签名错误：{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

/// 核心库结果。
pub type Result<T> = std::result::Result<T, Error>;
