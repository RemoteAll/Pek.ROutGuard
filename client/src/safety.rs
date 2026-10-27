//! 安全阀：**默认不碰用户的正式文件**。
//!
//! 三条硬约束（调试/试点阶段尤其重要）：
//! 1. **演练模式（`dry_run`，默认）**：只做规则判定与日志，绝不加密、不删除、不替换任何文件；
//! 2. **危险目录拒绝**：桌面 / 文档 / 下载 / 用户目录本身 / 盘符根 / 系统目录 一律不作为监控根
//!    （这些地方一旦误配置就是"整个用户资料被加密"，必须显式 `AllowRiskyRoots = true` 才放行）；
//! 3. **原文件进回收区**：实盘模式下加密成功后不直接删原文件，而是移到 `Data/Recovery/<日期>/`，
//!    保留期满再清理——出错能拿回来。
//!
//! 判定只做**路径字符串比较**，不访问任何文件内容。

use std::path::{Path, PathBuf};

/// 危险根路径的判定结果（`None` = 可以安全监控）。
pub fn risky_root_reason(path: &Path) -> Option<String> {
    let raw = path.to_string_lossy();
    let text = normalize(&raw);
    if text.is_empty() {
        return None;
    }

    // ① 盘符根（`C:\` / `D:`）：整盘加密＝灾难。
    if is_drive_root(&text) {
        return Some("盘符根目录（会监控整块磁盘）".to_string());
    }

    // ② 系统目录本身（子目录不拦：用户可能就想保护 `C:\ProgramData\某业务`）。
    for (name, label) in system_dirs() {
        if is_same(&text, &name) {
            return Some(format!("系统目录 {label}"));
        }
    }

    // ③ 用户目录本身与其常见资料夹（桌面/文档/下载/…）。
    if let Some(profile) = profile_dir() {
        if text == profile {
            return Some("用户主目录本身（会监控整个账号的资料）".to_string());
        }
        for (name, label) in user_folders(&profile) {
            if is_same(&text, &name) {
                return Some(format!("用户{label}（误配置会把个人资料全部加密）"));
            }
        }
    }
    None
}

/// 过滤监控根：返回（可用列表, 被拒列表）。
///
/// `allow_risky` 为 `true` 时全部放行（配置里显式承担风险后才这样）。
pub fn filter_roots(roots: &[String], allow_risky: bool) -> (Vec<String>, Vec<(String, String)>) {
    let mut keep = Vec::new();
    let mut rejected = Vec::new();
    for root in roots {
        let path = PathBuf::from(root);
        if !path.is_dir() {
            continue;
        }
        if allow_risky {
            keep.push(root.clone());
            continue;
        }
        match risky_root_reason(&path) {
            Some(reason) => rejected.push((root.clone(), reason)),
            None => keep.push(root.clone()),
        }
    }
    (keep, rejected)
}

/// 回收区目录：`Data/Recovery/<yyyyMMdd>`。
pub fn recovery_dir(base: &Path) -> PathBuf {
    base.join("Data")
        .join("Recovery")
        .join(chrono::Local::now().format("%Y%m%d").to_string())
}

/// 清理超过 `keep_days` 的回收区子目录，返回清理的目录数。
pub fn purge_recovery(base: &Path, keep_days: u32) -> usize {
    if keep_days == 0 {
        return 0;
    }
    let root = base.join("Data").join("Recovery");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return 0;
    };
    let cutoff = chrono::Local::now() - chrono::Duration::days(i64::from(keep_days));
    let cutoff_key = cutoff.format("%Y%m%d").to_string();
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // 目录名就是日期（yyyyMMdd），比日期小的整目录清理。
        if name.len() == 8 && name < cutoff_key {
            match std::fs::remove_dir_all(entry.path()) {
                Ok(()) => removed += 1,
                Err(e) => dhrust::warn!("清理回收区失败（{name}）：{e}"),
            }
        }
    }
    removed
}

fn normalize(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches(['\\', '/']).to_ascii_lowercase();
    trimmed.replace('/', "\\")
}

fn is_drive_root(text: &str) -> bool {
    let bytes = text.as_bytes();
    // "c:" （已被 trim_end 去掉尾部反斜杠）
    bytes.len() == 2 && bytes[1] == b':'
}

fn is_same(a: &str, b: &str) -> bool {
    a == b
}

fn system_dirs() -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for (env, label) in [
        ("SystemRoot", "Windows"),
        ("ProgramFiles", "Program Files"),
        ("ProgramFiles(x86)", "Program Files (x86)"),
        ("ProgramW6432", "Program Files"),
    ] {
        if let Ok(value) = std::env::var(env) {
            let path = normalize(&value);
            if !path.is_empty() {
                out.push((path, label));
            }
        }
    }
    out
}

fn profile_dir() -> Option<String> {
    std::env::var("USERPROFILE")
        .ok()
        .map(|value| normalize(&value))
        .filter(|value| !value.is_empty())
}

fn user_folders(profile: &str) -> Vec<(String, &'static str)> {
    let names = [
        ("Desktop", "桌面"),
        ("桌面", "桌面"),
        ("Documents", "文档目录"),
        ("文档", "文档目录"),
        ("Downloads", "下载目录"),
        ("下载", "下载目录"),
        ("Pictures", "图片目录"),
        ("图片", "图片目录"),
        ("Music", "音乐目录"),
        ("Videos", "视频目录"),
    ];
    let mut out = Vec::new();
    for (name, label) in names {
        out.push((format!("{profile}\\{}", name.to_ascii_lowercase()), label));
    }
    // OneDrive 重定向后的资料夹。
    if let Ok(one_drive) = std::env::var("OneDrive") {
        let one_drive = normalize(&one_drive);
        if !one_drive.is_empty() {
            out.push((one_drive.clone(), "OneDrive 目录"));
            for (name, label) in [("Desktop", "桌面"), ("Documents", "文档目录")] {
                out.push((
                    format!("{one_drive}\\{}", name.to_ascii_lowercase()),
                    label,
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_root_is_risky() {
        assert!(risky_root_reason(Path::new("C:\\")).is_some());
        assert!(risky_root_reason(Path::new("D:")).is_some());
        // 普通子目录不算危险
        assert!(risky_root_reason(Path::new("D:\\SecureWork")).is_none());
    }

    #[test]
    fn user_profile_and_desktop_are_risky() {
        if let Some(profile) = profile_dir() {
            let profile_path = PathBuf::from(profile.replace('\\', "/"));
            assert!(
                risky_root_reason(&profile_path).is_some(),
                "用户主目录本身必须被判为危险"
            );
            let desktop = PathBuf::from(format!("{}\\Desktop", profile).replace('\\', "/"));
            assert!(
                risky_root_reason(&desktop).is_some(),
                "桌面必须被判为危险"
            );
        }
    }

    #[test]
    fn filter_keeps_safe_and_reports_rejected() {
        let temp = std::env::temp_dir();
        let roots = vec![
            "C:\\".to_string(),
            temp.to_string_lossy().to_string(),
            "Z:\\definitely-not-exists-outguard".to_string(),
        ];
        let (keep, rejected) = filter_roots(&roots, false);
        assert_eq!(keep.len(), 1, "只有真实存在的安全目录被保留");
        assert!(keep[0].contains("Temp") || keep[0].to_ascii_lowercase().contains("temp"));
        assert_eq!(rejected.len(), 1, "盘符根被拒（不存在的目录直接过滤，不算拒）");
        assert!(rejected[0].1.contains("盘符根"));

        // 显式放行：盘符根也会被保留（危险操作，配置里必须显式开）
        let (keep_all, rejected_all) = filter_roots(&["C:\\".to_string()], true);
        assert_eq!(keep_all.len(), 1);
        assert!(rejected_all.is_empty());
    }

    #[test]
    fn recovery_dir_is_dated() {
        let base = PathBuf::from("C:\\OutGuard");
        let dir = recovery_dir(&base);
        let text = dir.to_string_lossy();
        assert!(text.contains("Recovery"));
        let name = dir.file_name().unwrap().to_string_lossy();
        assert_eq!(name.len(), 8, "目录名应为 yyyyMMdd：{name}");
    }
}
