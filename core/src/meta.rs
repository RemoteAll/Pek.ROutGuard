//! 透明加密的**文件元数据**（救命的 32 字节）。
//!
//! # 为什么需要它
//!
//! 透明加密要求"文件大小不变"，所以元数据不能写进文件头。但解密必须知道
//! **这个文件是谁**（`file_id` 参与 tweak 计算）。于是元数据放在 **NTFS 备用数据流**：
//! `D:\机密\方案.docx:oug`，主文件大小一个字节都不变。
//!
//! # 为什么必须带校验
//!
//! 救援工具在"驱动已损坏"的场景下工作，此时**任何静默的错误都是灾难**：
//! 若 ADS 被截断/篡改而工具照旧解密，出来的就是一堆无意义字节，用户可能以为
//! 原文件已毁。所以元数据自带 SHA-256 前 8 字节校验，校验不过一律报错、拒绝解密。
//!
//! # 布局（32 字节，小端）
//!
//! ```text
//! 0..4    magic   "OGM1"
//! 4..5    version 1
//! 5..6    flags   bit0=已加密
//! 6..8    reserved
//! 8..16   file_id（8 字节，参与 tweak）
//! 16..24  created_at（Unix 秒）
//! 24..32  checksum = SHA-256(bytes[0..24])[0..8]
//! ```

use sha2::{Digest, Sha256};

/// 元数据总长度
pub const META_LEN: usize = 32;
/// 魔数
pub const META_MAGIC: [u8; 4] = *b"OGM1";
/// 当前版本
pub const META_VERSION: u8 = 1;
/// NTFS 备用数据流名（访问时为 `文件路径:oug`）
pub const ADS_STREAM: &str = "oug";

/// 元数据里的标志位
pub const FLAG_ENCRYPTED: u8 = 0x01;

/// 文件元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// 文件身份（8 字节），参与 tweak 计算
    pub file_id: [u8; 8],
    /// 首次加密时间（Unix 秒）
    pub created_at: u64,
    /// 标志位
    pub flags: u8,
}

impl FileMeta {
    /// 新建（生成随机 file_id）。
    pub fn new_random() -> Self {
        Self {
            file_id: dhrust::random::bytes(8).try_into().unwrap_or([0u8; 8]),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            flags: FLAG_ENCRYPTED,
        }
    }

    /// 是否已标记为加密。
    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    /// 序列化为 32 字节。
    pub fn encode(&self) -> [u8; META_LEN] {
        let mut out = [0u8; META_LEN];
        out[0..4].copy_from_slice(&META_MAGIC);
        out[4] = META_VERSION;
        out[5] = self.flags;
        // 6..8 保留
        out[8..16].copy_from_slice(&self.file_id);
        out[16..24].copy_from_slice(&self.created_at.to_le_bytes());
        let sum = Self::checksum(&out[0..24]);
        out[24..32].copy_from_slice(&sum);
        out
    }

    /// 解析并**严格校验**。任何异常都报错，绝不返回"猜出来的"元数据。
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < META_LEN {
            return Err(format!(
                "元数据长度不足：期望 {META_LEN} 字节，实际 {}（ADS 可能被截断）",
                bytes.len()
            ));
        }
        if bytes[0..4] != META_MAGIC {
            return Err("元数据魔数不匹配（不是本产品的加密标记）".into());
        }
        let version = bytes[4];
        if version != META_VERSION {
            return Err(format!(
                "元数据版本不支持：{version}（本程序支持 {META_VERSION}）"
            ));
        }
        let expected = Self::checksum(&bytes[0..24]);
        if bytes[24..32] != expected {
            return Err("元数据校验失败（ADS 被篡改或损坏）——拒绝解密，请从备份恢复".into());
        }
        let mut file_id = [0u8; 8];
        file_id.copy_from_slice(&bytes[8..16]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[16..24]);
        Ok(Self {
            file_id,
            created_at: u64::from_le_bytes(ts),
            flags: bytes[5],
        })
    }

    fn checksum(head: &[u8]) -> [u8; 8] {
        let digest = Sha256::digest(head);
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FileMeta {
        FileMeta {
            file_id: [1, 2, 3, 4, 5, 6, 7, 8],
            created_at: 1_700_000_000,
            flags: FLAG_ENCRYPTED,
        }
    }

    #[test]
    fn roundtrip() {
        let meta = sample();
        let bytes = meta.encode();
        assert_eq!(bytes.len(), META_LEN);
        assert_eq!(FileMeta::decode(&bytes).expect("解析"), meta);
    }

    #[test]
    fn rejects_truncated() {
        let bytes = sample().encode();
        assert!(FileMeta::decode(&bytes[..16]).is_err(), "截断必须报错");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample().encode();
        bytes[0] = b'X';
        assert!(FileMeta::decode(&bytes).is_err(), "魔数错必须报错");
    }

    #[test]
    fn rejects_tampered_file_id() {
        // 篡改 file_id 必须被校验和抓住——否则会拿错误的 tweak 去解密，
        // 解出一堆垃圾还以为成功。
        let mut bytes = sample().encode();
        bytes[8] ^= 0xFF;
        let err = FileMeta::decode(&bytes).expect_err("篡改必须被发现");
        assert!(err.contains("校验失败"), "错误信息应指明校验失败，实际：{err}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = sample().encode();
        bytes[4] = 99;
        // 版本变化会连带让校验和失效，两种错误都算正确拒绝
        assert!(FileMeta::decode(&bytes).is_err());
    }

    #[test]
    fn random_ids_differ() {
        let a = FileMeta::new_random();
        let b = FileMeta::new_random();
        assert_ne!(a.file_id, b.file_id, "随机 file_id 不应重复");
        assert!(a.is_encrypted());
    }
}
