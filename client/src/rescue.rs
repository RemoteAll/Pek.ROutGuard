//! 救援工具：**不依赖内核驱动**的透明加密读写。
//!
//! 用途有三个，都很实在：
//! 1. **驱动没加载 / 崩溃时**，把被 XTS 加密的文件还原成明文；
//! 2. **验证 M2 算法链路**：把明文加密后再解密，逐字节比对，证明"能加密也能救回"；
//! 3. **换机/灾难恢复**：只要拿到策略密钥，文件在哪台机器上都能解开。
//!
//! 设计原则：**永不覆盖原件**。`decrypt` 只往指定输出目录写，`encrypt` 先写临时文件
//! 再原子替换，任何一步失败都保留原始数据。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use pek_outguard_core::meta::FileMeta;
use pek_outguard_core::xts::{BLOCK_LEN, FileId, XtsCipher};

use crate::ads;

/// 流式处理的缓冲大小（16 的倍数）
const CHUNK: usize = 256 * 1024;

/// 救援结果摘要
#[derive(Debug, Default)]
pub struct RescueReport {
    pub bytes: u64,
    pub file_id: FileId,
}

/// 把一个明文文件**原地**加密，并写入 ADS 元数据。
///
/// 先写临时文件再原子替换：中途失败不会毁掉原文件。
pub fn encrypt_file_in_place(path: &Path, cipher: &XtsCipher) -> Result<RescueReport, String> {
    let meta = match ads::read_meta(path)? {
        Some(existing) if existing.is_encrypted() => {
            return Err(format!(
                "{} 已经带加密标记（file_id 已存在），拒绝重复加密",
                path.display()
            ));
        }
        Some(existing) => existing,
        None => FileMeta::new_random(),
    };
    let file_id = meta.file_id;

    let mut src = std::fs::File::open(path)
        .map_err(|e| format!("打开源文件失败（{}）：{e}", path.display()))?;
    let total = src.metadata().map(|m| m.len()).unwrap_or(0);

    let temp = path.with_extension("oug-tmp");
    let mut out = std::fs::File::create(&temp)
        .map_err(|e| format!("创建临时文件失败（{}）：{e}", temp.display()))?;

    let mut buf = vec![0u8; CHUNK];
    let mut offset: u64 = 0;
    let result = (|| -> Result<u64, String> {
        loop {
            let n = src.read(&mut buf).map_err(|e| format!("读取源文件失败：{e}"))?;
            if n == 0 {
                break;
            }
            let full = n - (n % BLOCK_LEN);
            if full > 0 {
                cipher.encrypt_range(&file_id, offset, &mut buf[..full])?;
            }
            if n > full {
                // 尾部零头：位置必须 16 字节对齐
                cipher.encrypt_tail(&file_id, offset + full as u64, &mut buf[full..n])?;
            }
            out.write_all(&buf[..n]).map_err(|e| format!("写入临时文件失败：{e}"))?;
            offset += n as u64;
        }
        out.flush().map_err(|e| format!("刷盘失败：{e}"))?;
        Ok(offset)
    })();

    drop(out);
    match result {
        Ok(bytes) => {
            // 透明加密的硬要求：密文与明文**等长**。不等长说明逻辑有问题，宁可失败也不落盘
            if bytes != total {
                let _ = std::fs::remove_file(&temp);
                return Err(format!(
                    "加密后长度异常（原文 {total} 字节，密文 {bytes} 字节），已中止且未改动原文件"
                ));
            }
            // 原子替换：失败时原文件仍在
            dhrust::io::safe_replace_file(&temp, path).map_err(|e| {
                let _ = std::fs::remove_file(&temp);
                format!("替换原文件失败（原文件未改动）：{e}")
            })?;
            // 再写元数据：万一这里失败，文件已是密文但没标记 → 明确报错让用户知道
            ads::write_meta(path, &meta).map_err(|e| {
                format!("加密完成但写元数据失败：{e}\n  文件现在没有加密标记，请立即联系管理员（可用 rescue decrypt 配合 file_id 手工恢复）")
            })?;
            Ok(RescueReport {
                bytes,
                file_id,
            })
        }
        Err(e) => {
            let _ = std::fs::remove_file(&temp);
            Err(format!("加密失败（原文件未改动）：{e}"))
        }
    }
}

/// 把加密文件解密到 `out_dir`，**不动原文件**。
pub fn decrypt_file_to(
    path: &Path,
    out_dir: &Path,
    cipher: &XtsCipher,
) -> Result<(PathBuf, RescueReport), String> {
    let meta = ads::read_meta(path)?
        .ok_or_else(|| format!("{} 没有加密标记（缺 ADS:oug），无法确定文件身份", path.display()))?;
    if !meta.is_encrypted() {
        return Err(format!("{} 的元数据未标记为已加密", path.display()));
    }
    let file_id = meta.file_id;

    let name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_else(|| "restored".to_string());
    std::fs::create_dir_all(out_dir).map_err(|e| format!("创建输出目录失败：{e}"))?;
    let target = out_dir.join(name);
    if target.exists() {
        return Err(format!("输出文件已存在，拒绝覆盖：{}", target.display()));
    }

    let mut src = std::fs::File::open(path)
        .map_err(|e| format!("打开加密文件失败（{}）：{e}", path.display()))?;
    let mut out =
        std::fs::File::create(&target).map_err(|e| format!("创建输出文件失败：{e}"))?;

    let mut buf = vec![0u8; CHUNK];
    let mut offset: u64 = 0;
    let result = (|| -> Result<u64, String> {
        loop {
            let n = src.read(&mut buf).map_err(|e| format!("读取加密文件失败：{e}"))?;
            if n == 0 {
                break;
            }
            let full = n - (n % BLOCK_LEN);
            if full > 0 {
                cipher.decrypt_range(&file_id, offset, &mut buf[..full])?;
            }
            if n > full {
                cipher.decrypt_tail(&file_id, offset + full as u64, &mut buf[full..n])?;
            }
            out.write_all(&buf[..n]).map_err(|e| format!("写入失败：{e}"))?;
            offset += n as u64;
        }
        out.flush().map_err(|e| format!("刷盘失败：{e}"))?;
        Ok(offset)
    })();

    drop(out);
    match result {
        Ok(bytes) => Ok((
            target,
            RescueReport {
                bytes,
                file_id,
            },
        )),
        Err(e) => {
            let _ = std::fs::remove_file(&target);
            Err(format!("解密失败（原文件未改动，输出已清理）：{e}"))
        }
    }
}

/// 读文件元数据（不解析内容）。
pub fn describe(path: &Path) -> Result<String, String> {
    match ads::read_meta(path)? {
        None => Ok(format!("{}：未加密（没有 :oug 元数据）", path.display())),
        Some(meta) => {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            Ok(format!(
                "{}：{}\n  file_id   = {}\n  加密时间  = {}\n  文件大小  = {size} 字节（明文与密文等长）",
                path.display(),
                if meta.is_encrypted() { "已加密" } else { "标记存在但未加密" },
                hex(&meta.file_id),
                meta.created_at,
            ))
        }
    }
}

/// 校验一个加密文件能否完整解密（逐块解到 sink，不落盘）。
///
/// 用于"批量体检"：在真正恢复之前先确认每个文件都能解得开。
pub fn verify(path: &Path, cipher: &XtsCipher) -> Result<u64, String> {
    let meta = ads::read_meta(path)?
        .ok_or_else(|| format!("{} 没有加密标记", path.display()))?;
    let mut src = std::fs::File::open(path)
        .map_err(|e| format!("打开失败（{}）：{e}", path.display()))?;
    let mut buf = vec![0u8; CHUNK];
    let mut offset: u64 = 0;
    let mut sink = std::io::sink();
    loop {
        let n = src.read(&mut buf).map_err(|e| format!("读取失败：{e}"))?;
        if n == 0 {
            break;
        }
        let full = n - (n % BLOCK_LEN);
        if full > 0 {
            cipher.decrypt_range(&meta.file_id, offset, &mut buf[..full])?;
        }
        if n > full {
            cipher.decrypt_tail(&meta.file_id, offset + full as u64, &mut buf[full..n])?;
        }
        sink.write_all(&buf[..n]).map_err(|e| format!("丢弃写入失败：{e}"))?;
        offset += n as u64;
    }
    Ok(offset)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 从十六进制字符串解析 XTS 密钥（64 字节 = 128 个十六进制字符）。
pub fn parse_key_hex(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() != 128 {
        return Err(format!(
            "XTS 密钥应为 128 个十六进制字符（64 字节），实际 {}",
            cleaned.len()
        ));
    }
    let mut out = Vec::with_capacity(64);
    let bytes = cleaned.as_bytes();
    for i in (0..128).step_by(2) {
        let s = std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| format!("非法字符：{e}"))?;
        out.push(u8::from_str_radix(s, 16).map_err(|e| format!("非法十六进制：{e}"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oug-rescue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    fn cipher() -> XtsCipher {
        XtsCipher::new(&(0u8..64).collect::<Vec<u8>>()).expect("建 cipher")
    }

    #[test]
    fn encrypt_then_decrypt_restores_exact_bytes() {
        let dir = temp_dir();
        let file = dir.join("方案.docx");
        // 故意用非 16 倍数的长度，覆盖尾部逻辑
        let plain: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&file, &plain).expect("建文件");

        let report = encrypt_file_in_place(&file, &cipher()).expect("加密");
        assert_eq!(report.bytes, plain.len() as u64);

        let on_disk = std::fs::read(&file).expect("读密文");
        assert_eq!(on_disk.len(), plain.len(), "加密后大小必须不变");
        assert_ne!(on_disk, plain, "磁盘上必须是密文");

        let out_dir = dir.join("out");
        let (restored, _) = decrypt_file_to(&file, &out_dir, &cipher()).expect("解密");
        let got = std::fs::read(&restored).expect("读还原文件");
        assert_eq!(got, plain, "还原内容必须与原文逐字节一致");
        // 原文件仍是密文（救援不改原件）
        assert_eq!(std::fs::read(&file).expect("读密文"), on_disk);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_is_idempotent_guard() {
        let dir = temp_dir();
        let file = dir.join("a.txt");
        std::fs::write(&file, b"data").expect("建文件");
        encrypt_file_in_place(&file, &cipher()).expect("第一次加密");
        let err = encrypt_file_in_place(&file, &cipher()).expect_err("重复加密必须被拒绝");
        assert!(err.contains("已经带加密标记"), "错误信息应说明原因，实际：{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_produces_garbage_not_silent_success() {
        let dir = temp_dir();
        let file = dir.join("b.txt");
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(4);
        std::fs::write(&file, &plain).expect("建文件");
        encrypt_file_in_place(&file, &cipher()).expect("加密");

        let other = XtsCipher::new(&(100u8..164).collect::<Vec<u8>>()).expect("另一把 key");
        let out_dir = dir.join("out");
        let (restored, _) = decrypt_file_to(&file, &out_dir, &other).expect("能跑完");
        let got = std::fs::read(&restored).expect("读");
        assert_ne!(got, plain, "用错密钥不可能还原出原文");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_readable_file() {
        let dir = temp_dir();
        let file = dir.join("c.txt");
        std::fs::write(&file, vec![7u8; 5000]).expect("建文件");
        encrypt_file_in_place(&file, &cipher()).expect("加密");
        let bytes = verify(&file, &cipher()).expect("体检");
        assert_eq!(bytes, 5000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unmarked_file_is_rejected_with_clear_reason() {
        let dir = temp_dir();
        let file = dir.join("d.txt");
        std::fs::write(&file, b"plain").expect("建文件");
        let err = decrypt_file_to(&file, &dir.join("out"), &cipher()).expect_err("必须拒绝");
        assert!(err.contains("没有加密标记"), "错误信息应可定位，实际：{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_hex_parsing() {
        let hex: String = (0u8..64).map(|b| format!("{b:02x}")).collect();
        let key = parse_key_hex(&hex).expect("解析");
        assert_eq!(key.len(), 64);
        assert_eq!(key[0], 0);
        assert_eq!(key[63], 63);
        assert!(parse_key_hex("abcd").is_err(), "长度不对必须报错");
        assert!(parse_key_hex(&"zz".repeat(64)).is_err(), "非法字符必须报错");
    }
}
