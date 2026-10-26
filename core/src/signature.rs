//! 设备密钥（Ed25519）与签名字符串编解码。
//!
//! 用途：
//! - 客户端注册时生成密钥对，公钥登记服务端；后续每个请求用私钥签名（防伪造/防重放）。
//! - 服务端签发卸载令牌 / 升级包签名；客户端内置服务端公钥验签。
//!
//! 私钥的**持久化**由客户端负责（Windows DPAPI / Linux 0600 机器密钥包裹），本模块只做运算。

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{Error, Result};

/// 设备私钥种子/公钥/签名长度。
pub const SEED_LEN: usize = 32;
/// 公钥长度。
pub const PUBLIC_KEY_LEN: usize = 32;
/// 签名长度。
pub const SIGNATURE_LEN: usize = 64;

/// 设备密钥（持有私钥）。
#[derive(Clone)]
pub struct DeviceKey {
    signing: SigningKey,
}

impl DeviceKey {
    /// 生成新密钥（OS 熵）。
    pub fn generate() -> Self {
        let seed: [u8; SEED_LEN] = crate::crypto::random_array();
        Self::from_seed(&seed)
    }

    /// 从种子恢复（客户端持久化的是种子）。
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// 公钥（32 字节）。
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// 公钥（base64）。
    pub fn public_key_b64(&self) -> String {
        encode(&self.public_key())
    }

    /// 签名。
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// 签名（base64）。
    pub fn sign_b64(&self, message: &[u8]) -> String {
        encode(&self.sign(message))
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 私钥不入日志。
        f.debug_struct("DeviceKey")
            .field("public_key", &self.public_key_b64())
            .finish()
    }
}

/// 验签（base64 输入）。
pub fn verify_b64(public_key_b64: &str, message: &[u8], signature_b64: &str) -> Result<()> {
    let public_key = decode(public_key_b64)?;
    let signature = decode(signature_b64)?;
    verify(&public_key, message, &signature)
}

/// 验签（原始字节输入）。
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key: [u8; PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| Error::Signature(format!("公钥长度错误：期望 {PUBLIC_KEY_LEN}")))?;
    let signature: [u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| Error::Signature(format!("签名长度错误：期望 {SIGNATURE_LEN}")))?;

    let verifying = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| Error::Signature(format!("公钥非法：{e}")))?;
    verifying
        .verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::Signature("验签失败".into()))
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|e| Error::Signature(format!("Base64 解码失败：{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = DeviceKey::generate();
        let message = b"POST\n/api/client/heartbeat\n100\nnonce\nabc";
        let signature = key.sign_b64(message);

        verify_b64(&key.public_key_b64(), message, &signature).expect("验签成功");
        assert!(verify_b64(&key.public_key_b64(), b"other", &signature).is_err());
    }

    #[test]
    fn restored_seed_produces_same_key() {
        let seed: [u8; SEED_LEN] = crate::crypto::random_array();
        let a = DeviceKey::from_seed(&seed);
        let b = DeviceKey::from_seed(&seed);
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let key = DeviceKey::generate();
        let text = format!("{key:?}");
        assert!(text.contains("public_key"));
        assert!(!text.contains(&crate::crypto::hex(&key.sign(b"probe"))));
    }

    #[test]
    fn bad_inputs_are_rejected() {
        assert!(verify(&[0u8; 3], b"x", &[0u8; 64]).is_err());
        assert!(verify(&[0u8; 32], b"x", &[0u8; 8]).is_err());
        assert!(verify_b64("!!!", b"x", "!!!").is_err());
    }
}
