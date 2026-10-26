//! 主密钥（MasterKey）托管：`Data/master.key`（64 位十六进制，Unix 下 0600）。
//!
//! 主密钥**不入库、不出网**：策略密钥由 `HKDF(MasterKey, policy/{id}/v{n})` 派生。
//! 丢失主密钥 = 所有加密文件不可解，因此在首次生成时必须提示备份。

use std::path::{Path, PathBuf};

use pek_outguard_core::crypto::{self, KEY_LEN};

/// 主密钥文件（相对程序基目录）。
pub const KEY_RELATIVE: &str = "Data/master.key";

/// 读取或首次生成主密钥。
///
/// 返回 `(key, created)`：`created=true` 表示本次新生成，调用方应提示用户备份。
pub fn load_or_create(base: &Path) -> Result<([u8; KEY_LEN], bool), String> {
    let path = key_path(base);
    if path.is_file() {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("读取主密钥失败（{}）：{e}", path.display()))?;
        let bytes = decode_hex(text.trim())?;
        if bytes.len() != KEY_LEN {
            return Err(format!(
                "主密钥长度非法（{}）：期望 {KEY_LEN} 字节，实际 {} 字节",
                path.display(),
                bytes.len()
            ));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        return Ok((key, false));
    }

    let key: [u8; KEY_LEN] = crypto::random_array();
    write_secret(&path, &crypto::hex(&key))?;
    Ok((key, true))
}

/// 主密钥文件路径。
pub fn key_path(base: &Path) -> PathBuf {
    base.join(KEY_RELATIVE)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("主密钥十六进制长度非法：{}", text.len()));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let high = hex_val(pair[0])?;
        let low = hex_val(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("主密钥含非法字符：{}", other as char)),
    }
}

/// 写敏感文件：Unix 下 0600；Windows 依赖目录 ACL（部署时限制 Data/ 权限）。
fn write_secret(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
    }
    std::fs::write(path, text).map_err(|e| format!("写入主密钥失败（{}）：{e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "outguard-keys-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn creates_then_reuses_same_key() {
        let dir = temp_dir("reuse");
        std::fs::create_dir_all(&dir).expect("建目录");

        let (first, created) = load_or_create(&dir).expect("首次生成");
        assert!(created);
        let (second, created) = load_or_create(&dir).expect("再次读取");
        assert!(!created);
        assert_eq!(first, second);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bad_key_file() {
        let dir = temp_dir("bad");
        std::fs::create_dir_all(dir.join("Data")).expect("建目录");
        std::fs::write(dir.join(KEY_RELATIVE), "zz").expect("写坏文件");
        assert!(load_or_create(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
