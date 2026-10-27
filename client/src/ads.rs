//! NTFS 备用数据流（ADS）里存放透明加密的文件元数据。
//!
//! 访问方式：`D:\机密\方案.docx:oug`。主文件**大小不变**，符合"对应用透明"的要求。
//!
//! # 已知限制（必须写进交付文档）
//!
//! - 复制到 **FAT32 / exFAT / 多数 U 盘**会丢掉 ADS → 文件成了没有身份的密文；
//! - 部分备份/同步工具不保留 ADS；
//! - 若 ADS 丢失，本机还能靠 `Data/DriverIndex.db`（侧表，M2 实现）按路径找回 file_id；
//! - 因此"复制到不支持 ADS 的位置"应在客户端拦截（后续的复制/拖拽管控一并做）。

use std::path::{Path, PathBuf};

use pek_outguard_core::meta::{self, FileMeta};

/// 构造 ADS 路径：`D:\a.docx` → `D:\a.docx:oug`
pub fn ads_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(":");
    raw.push(meta::ADS_STREAM);
    PathBuf::from(raw)
}

/// 读取元数据。返回 `Ok(None)` 表示该文件没有本产品的加密标记（不是错误）。
pub fn read_meta(path: &Path) -> Result<Option<FileMeta>, String> {
    let ads = ads_path(path);
    match std::fs::read(&ads) {
        Ok(bytes) => FileMeta::decode(&bytes)
            .map(Some)
            .map_err(|e| format!("{} 的加密元数据不可用：{e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("读取加密元数据失败（{}）：{e}", ads.display())),
    }
}

/// 写入元数据（覆盖已有）。
pub fn write_meta(path: &Path, data: &FileMeta) -> Result<(), String> {
    let ads = ads_path(path);
    std::fs::write(&ads, data.encode())
        .map_err(|e| format!("写入加密元数据失败（{}）：{e}", ads.display()))
}

/// 删除元数据（解密/取消加密时用）。
pub fn remove_meta(path: &Path) -> Result<(), String> {
    let ads = ads_path(path);
    match std::fs::remove_file(&ads) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("删除加密元数据失败（{}）：{e}", ads.display())),
    }
}

/// 该文件是否带本产品的加密标记。
pub fn is_encrypted(path: &Path) -> bool {
    matches!(read_meta(path), Ok(Some(meta)) if meta.is_encrypted())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oug-ads-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        dir
    }

    #[test]
    fn ads_path_appends_stream_name() {
        let p = ads_path(Path::new(r"D:\机密\方案.docx"));
        assert_eq!(p.to_string_lossy(), r"D:\机密\方案.docx:oug");
    }

    #[test]
    fn write_read_remove_roundtrip() {
        let dir = temp_dir();
        let file = dir.join("方案.docx");
        std::fs::write(&file, b"hello").expect("建文件");

        // 未标记
        assert_eq!(read_meta(&file).expect("读"), None);
        assert!(!is_encrypted(&file));

        // 写入后能读回
        let meta = FileMeta::new_random();
        write_meta(&file, &meta).expect("写");
        assert_eq!(read_meta(&file).expect("读").expect("应有"), meta);
        assert!(is_encrypted(&file));

        // 主文件内容与大小不受影响（这是"透明"的硬要求）
        assert_eq!(std::fs::read(&file).expect("读主文件"), b"hello");

        // 删除后回到未标记
        remove_meta(&file).expect("删");
        assert_eq!(read_meta(&file).expect("读"), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_ads_is_reported_not_ignored() {
        let dir = temp_dir();
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").expect("建文件");
        write_meta(&file, &FileMeta::new_random()).expect("写");

        // 破坏 ADS 内容
        let ads = ads_path(&file);
        let mut bytes = std::fs::read(&ads).expect("读 ADS");
        bytes[8] ^= 0xFF;
        std::fs::write(&ads, &bytes).expect("写回");

        let err = read_meta(&file).expect_err("篡改必须报错");
        assert!(err.contains("元数据"), "错误信息应指明元数据问题，实际：{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
