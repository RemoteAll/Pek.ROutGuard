//! 密钥派生与分块加密原语。
//!
//! - 策略密钥 `PolicyKey = HKDF-SHA256(MasterKey, "policy/{id}/v{n}")`：同一主密钥可派生任意规则集密钥，
//!   轮换只提升 `key_version`，历史版本仍可派生 → 旧文件仍能解密。
//! - 文件密钥 `DEK` 每文件随机，用 `PolicyKey` 以 AES-256-GCM 包裹（AAD = 头部 JSON 的 SHA-256）。
//! - 分块 nonce = `prefix(8) || 块序号 LE(4)`；每文件随机 prefix，块序号单调递增，全局不重复。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// 密钥长度（AES-256）。
pub const KEY_LEN: usize = 32;
/// GCM nonce 长度。
pub const GCM_NONCE_LEN: usize = 12;
/// GCM tag 长度（附在密文尾部）。
pub const GCM_TAG_LEN: usize = 16;

/// HKDF 固定 salt（同一主密钥下不同用途互相隔离）。
const POLICY_KDF_SALT: &[u8] = b"pek-outguard-policy-kdf-v1";

/// 计算 SHA-256。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// 小写十六进制编码（签名载荷/事件 ID 用）。
pub fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0F) as usize] as char);
    }
    out
}

/// 生成 `N` 字节安全随机数据（复用 `dhrust::random`，OS 熵）。
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&dhrust::random::bytes(N));
    out
}

/// 派生规则集策略密钥。
///
/// `key_version` 从 1 开始；轮换时递增，旧版本仍可派生（用于解密历史文件）。
pub fn derive_policy_key(
    master: &[u8; KEY_LEN],
    policy_id: &str,
    key_version: u32,
) -> Result<[u8; KEY_LEN]> {
    let policy_id = policy_id.trim();
    if policy_id.is_empty() {
        return Err(Error::Crypto("策略 ID 不能为空".into()));
    }
    if key_version == 0 {
        return Err(Error::Crypto("策略密钥版本必须从 1 开始".into()));
    }

    let hkdf = Hkdf::<Sha256>::new(Some(POLICY_KDF_SALT), master);
    let mut okm = [0u8; KEY_LEN];
    let info = format!("{policy_id}/v{key_version}");
    hkdf.expand(info.as_bytes(), &mut okm)
        .map_err(|e| Error::Crypto(format!("策略密钥派生失败：{e:?}")))?;
    Ok(okm)
}

/// 用 KEK 包裹文件密钥（DEK）。
///
/// 返回 `nonce(12) || AES-256-GCM 密文(32 + tag16)`。
pub fn wrap_key(kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; GCM_NONCE_LEN] = random_array();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: dek,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(format!("文件密钥包裹失败：{e}")))?;

    let mut out = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// 用 KEK 拆包文件密钥。
pub fn unwrap_key(kek: &[u8; KEY_LEN], packed: &[u8], aad: &[u8]) -> Result<[u8; KEY_LEN]> {
    let expected = GCM_NONCE_LEN + KEY_LEN + GCM_TAG_LEN;
    if packed.len() != expected {
        return Err(Error::Format(format!(
            "KeyBlock 长度异常：期望 {expected}，实际 {}",
            packed.len()
        )));
    }

    let (nonce, ciphertext) = packed.split_at(GCM_NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("文件密钥解包失败（策略密钥不匹配或容器被篡改）".into()))?;

    let mut dek = [0u8; KEY_LEN];
    dek.copy_from_slice(&plain);
    Ok(dek)
}

/// 构造分块 nonce：`prefix(8) || 块序号 LE(4)`。
///
/// 块序号上限 `u32::MAX`；1 MiB 分块 ⇒ 单文件理论上限约 4 PB，足够。
pub fn chunk_nonce(prefix: &[u8; 8], index: u64) -> [u8; GCM_NONCE_LEN] {
    let mut nonce = [0u8; GCM_NONCE_LEN];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&(index as u32).to_le_bytes());
    nonce
}

/// 加密一个分块。
pub fn encrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    plain: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plain,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(format!("分块加密失败：{e}")))
}

/// 解密一个分块。
pub fn decrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("分块解密失败（密钥不匹配或数据被篡改）".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    #[test]
    fn derive_is_stable_and_version_scoped() {
        let a = derive_policy_key(&master(), "policy-a", 1).expect("派生成功");
        let b = derive_policy_key(&master(), "policy-a", 1).expect("派生成功");
        let c = derive_policy_key(&master(), "policy-a", 2).expect("派生成功");
        let d = derive_policy_key(&master(), "policy-b", 1).expect("派生成功");

        assert_eq!(a, b, "同参数必须稳定");
        assert_ne!(a, c, "不同版本必须不同");
        assert_ne!(a, d, "不同规则集必须不同");
    }

    #[test]
    fn derive_rejects_empty_id_and_zero_version() {
        assert!(derive_policy_key(&master(), "  ", 1).is_err());
        assert!(derive_policy_key(&master(), "p", 0).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = derive_policy_key(&master(), "p", 1).expect("派生成功");
        let dek: [u8; KEY_LEN] = random_array();
        let aad = sha256(b"header");

        let packed = wrap_key(&kek, &dek, &aad).expect("包裹成功");
        assert_eq!(packed.len(), GCM_NONCE_LEN + KEY_LEN + GCM_TAG_LEN);
        let back = unwrap_key(&kek, &packed, &aad).expect("拆包成功");
        assert_eq!(back, dek);
    }

    #[test]
    fn unwrap_fails_on_wrong_key_or_aad() {
        let kek = derive_policy_key(&master(), "p", 1).expect("派生成功");
        let other = derive_policy_key(&master(), "p", 2).expect("派生成功");
        let dek: [u8; KEY_LEN] = random_array();
        let aad = sha256(b"header");

        let packed = wrap_key(&kek, &dek, &aad).expect("包裹成功");
        assert!(unwrap_key(&other, &packed, &aad).is_err(), "换钥必须失败");
        assert!(
            unwrap_key(&kek, &packed, &sha256(b"other")).is_err(),
            "AAD 变化必须失败"
        );
    }

    #[test]
    fn chunk_nonce_is_unique_per_index() {
        let prefix = [3u8; 8];
        let a = chunk_nonce(&prefix, 0);
        let b = chunk_nonce(&prefix, 1);
        let c = chunk_nonce(&prefix, u32::MAX as u64);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(&a[..8], &prefix);
    }

    #[test]
    fn chunk_roundtrip_and_tamper_detection() {
        let key: [u8; KEY_LEN] = random_array();
        let nonce = chunk_nonce(&[1u8; 8], 2);
        let aad = sha256(b"hdr");
        let plain = b"hello outguard";

        let ciphertext = encrypt_chunk(&key, &nonce, plain, &aad).expect("加密成功");
        let back = decrypt_chunk(&key, &nonce, &ciphertext, &aad).expect("解密成功");
        assert_eq!(back, plain);

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;
        assert!(decrypt_chunk(&key, &nonce, &tampered, &aad).is_err());
    }

    #[test]
    fn hex_shape() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
