//! 与内核过滤驱动 `PekOutGuardFilter.sys` 的控制通道（M1）。
//!
//! 驱动暴露设备 `\\.\PekOutGuardFilter`，本模块封装三类操作：
//! - 读统计 / 版本（确认驱动是否在跑、规则是否生效）
//! - 下发规则表（NT 路径前缀 + 扩展名）
//! - 开关与清零
//!
//! **路径口径**：内核拿到的是 NT 路径（`\Device\HarddiskVolume3\...`），
//! 用户态规则里的 `D:\...` 必须先经 [`dos_to_nt_prefix`] 换算，否则永远匹配不上。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, QueryDosDeviceW,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// 驱动设备名（用户态可见的符号链接）
const DEVICE_PATH: &str = "\\\\.\\PekOutGuardFilter";

const OUG_DEVICE_TYPE: u32 = 0x8A00;

const fn ctl_code(function: u32, method: u32, access: u32) -> u32 {
    (OUG_DEVICE_TYPE << 16) | (access << 14) | (function << 2) | method
}

const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const IOCTL_GET_STATS: u32 = ctl_code(0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_SET_ENABLED: u32 = ctl_code(0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_GET_VERSION: u32 = ctl_code(0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_SET_RULES: u32 = ctl_code(0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_RESET_STATS: u32 = ctl_code(0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// 规则表上限（必须与驱动 `main.c` 的常量一致）
pub const MAX_PREFIXES: usize = 16;
pub const MAX_PATH: usize = 260;
pub const MAX_EXTS: usize = 32;
pub const MAX_EXT_LEN: usize = 16;

/// 与驱动 `OUG_STATS` 字节级一致。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverStats {
    pub create: i64,
    pub read: i64,
    pub write: i64,
    pub set_info: i64,
    pub cleanup: i64,
    pub rule_hit: i64,
    pub rule_miss: i64,
    pub rule_eval_error: i64,
    pub rules_version: u32,
    pub path_prefix_count: u32,
    pub ext_count: u32,
    pub last_hit: [u16; MAX_PATH],
    // —— M2a：ADS 元数据探测（驱动只读，不改数据）——
    pub ads_hit: i64,
    pub ads_absent: i64,
    pub ads_broken: i64,
    pub ads_error: i64,
    pub last_ads_file_id: [u8; 8],
    pub ads_skipped: i64,
    /// 魔数/版本合法但 SHA-256 校验和对不上：标记被篗改或写坏了
    pub ads_tampered: i64,
}

impl Default for DriverStats {
    fn default() -> Self {
        Self {
            create: 0,
            read: 0,
            write: 0,
            set_info: 0,
            cleanup: 0,
            rule_hit: 0,
            rule_miss: 0,
            rule_eval_error: 0,
            rules_version: 0,
            path_prefix_count: 0,
            ext_count: 0,
            last_hit: [0u16; MAX_PATH],
            ads_hit: 0,
            ads_absent: 0,
            ads_broken: 0,
            ads_error: 0,
            last_ads_file_id: [0u8; 8],
            ads_skipped: 0,
            ads_tampered: 0,
        }
    }
}

impl DriverStats {
    /// 最近一次命中的路径（NT 路径）
    pub fn last_hit_display(&self) -> String {
        let len = self.last_hit.iter().position(|&c| c == 0).unwrap_or(0);
        String::from_utf16_lossy(&self.last_hit[..len])
    }

    /// 最近一次读到的 file_id（十六进制）；全 0 表示还没读到过
    pub fn last_file_id_display(&self) -> String {
        if self.last_ads_file_id.iter().all(|&b| b == 0) {
            return String::new();
        }
        self.last_ads_file_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// 与驱动 `OUG_RULES` 字节级一致。
#[repr(C)]
pub struct DriverRules {
    pub version: u32,
    pub path_prefix_count: u32,
    pub path_prefixes: [[u16; MAX_PATH]; MAX_PREFIXES],
    pub ext_count: u32,
    pub extensions: [[u16; MAX_EXT_LEN]; MAX_EXTS],
}

impl Default for DriverRules {
    fn default() -> Self {
        Self {
            version: 0,
            path_prefix_count: 0,
            path_prefixes: [[0u16; MAX_PATH]; MAX_PREFIXES],
            ext_count: 0,
            extensions: [[0u16; MAX_EXT_LEN]; MAX_EXTS],
        }
    }
}

impl DriverRules {
    /// 构造规则表：`prefixes` 是 NT 路径前缀，`exts` 是带点的扩展名（大小写不敏感）。
    pub fn new(version: u32, prefixes: &[String], exts: &[String]) -> Result<Self, String> {
        if prefixes.len() > MAX_PREFIXES {
            return Err(format!("路径前缀最多 {MAX_PREFIXES} 条，给了 {}", prefixes.len()));
        }
        if exts.len() > MAX_EXTS {
            return Err(format!("扩展名最多 {MAX_EXTS} 条，给了 {}", exts.len()));
        }
        let mut rules = Self {
            version,
            path_prefix_count: prefixes.len() as u32,
            ..Default::default()
        };
        for (i, prefix) in prefixes.iter().enumerate() {
            write_wstr(&mut rules.path_prefixes[i], prefix)
                .map_err(|_| format!("路径前缀过长（上限 {MAX_PATH}）：{prefix}"))?;
        }
        for (i, ext) in exts.iter().enumerate() {
            write_wstr(&mut rules.extensions[i], ext)
                .map_err(|_| format!("扩展名过长（上限 {MAX_EXT_LEN}）：{ext}"))?;
        }
        rules.ext_count = exts.len() as u32;
        Ok(rules)
    }
}

fn write_wstr(dest: &mut [u16], src: &str) -> Result<(), ()> {
    let utf16: Vec<u16> = src.encode_utf16().collect();
    if utf16.len() + 1 > dest.len() {
        return Err(());
    }
    dest[..utf16.len()].copy_from_slice(&utf16);
    dest[utf16.len()] = 0;
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// 驱动控制通道句柄。
pub struct DriverClient {
    handle: HANDLE,
}

impl DriverClient {
    /// 打开驱动控制设备。驱动未加载时返回可读的错误（不是 panic）。
    pub fn open() -> Result<Self, String> {
        let path = wide(DEVICE_PATH);
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(format!(
                "打开驱动设备失败（错误码 {code}）：{}\n  常见原因：①驱动没加载（先跑 driver\\install.ps1）\
                 \n            ②未开启测试签名（bcdedit /set testsigning on + 重启）\
                 \n            ③驱动加载失败（fltmc filters 看不到 PekOutGuardFilter）",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { handle })
    }

    fn call(&self, code: u32, input: Option<&[u8]>, out_len: usize) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; out_len.max(1)];
        let mut returned: u32 = 0;
        let in_ptr = input.map(|b| b.as_ptr() as *const _).unwrap_or(std::ptr::null());
        let in_len = input.map(|b| b.len() as u32).unwrap_or(0);
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                code,
                in_ptr,
                in_len,
                out.as_mut_ptr() as *mut _,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "IOCTL 0x{code:08X} 失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        out.truncate(returned as usize);
        Ok(out)
    }

    /// 驱动版本（高 16 位主版本，低 16 位次版本）。
    pub fn version(&self) -> Result<(u16, u16), String> {
        let bytes = self.call(IOCTL_GET_VERSION, None, 4)?;
        if bytes.len() < 4 {
            return Err("驱动返回的版本数据不足".into());
        }
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(((value >> 16) as u16, value as u16))
    }

    /// 读统计快照。
    pub fn stats(&self) -> Result<DriverStats, String> {
        let size = std::mem::size_of::<DriverStats>();
        let bytes = self.call(IOCTL_GET_STATS, None, size)?;
        if bytes.len() < size {
            return Err(format!(
                "驱动返回的统计长度不足（期望 {size}，实际 {}）——驱动与客户端版本不一致？",
                bytes.len()
            ));
        }
        // SAFETY: 驱动返回的是 POD 结构，长度已校验。
        Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const DriverStats) })
    }

    /// 下发规则表（整块覆盖）。
    pub fn set_rules(&self, rules: &DriverRules) -> Result<(), String> {
        let bytes = unsafe {
            std::slice::from_raw_parts(rules as *const DriverRules as *const u8, std::mem::size_of::<DriverRules>())
        };
        self.call(IOCTL_SET_RULES, Some(bytes), 0)?;
        Ok(())
    }

    /// 开关（关闭时仍加载，但不再判定）。
    pub fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        let value: i32 = if enabled { 1 } else { 0 };
        self.call(IOCTL_SET_ENABLED, Some(&value.to_le_bytes()), 0)?;
        Ok(())
    }

    /// 统计清零。
    pub fn reset_stats(&self) -> Result<(), String> {
        self.call(IOCTL_RESET_STATS, None, 0)?;
        Ok(())
    }
}

impl Drop for DriverClient {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// 把 `D:\...` 这类 DOS 路径换算成内核看到的 NT 路径前缀。
///
/// 例：`D:\项目\机密` → `\Device\HarddiskVolume3\项目\机密`
pub fn dos_to_nt_path(path: &Path) -> Result<String, String> {
    let text = path.to_string_lossy().to_string();
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' {
        return Err(format!("只支持带盘符的绝对路径：{text}"));
    }
    let drive = &text[..2]; // 例如 "D:"
    let mut buf = vec![0u16; 1024];
    let drive_w = wide(drive);
    let len = unsafe { QueryDosDeviceW(drive_w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        return Err(format!(
            "QueryDosDevice 失败（盘符 {drive}）：{}",
            std::io::Error::last_os_error()
        ));
    }
    let device = String::from_utf16_lossy(&buf[..len as usize - 1]);
    let rest = text[2..].trim_start_matches(['\\', '/']);
    Ok(if rest.is_empty() {
        device
    } else {
        format!("{device}\\{}", rest.replace('/', "\\"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_layout_matches_driver() {
        // 驱动侧：5+3 个 LONGLONG(64) + 3 个 ULONG(12) + WCHAR[260](520) = 596 → 对齐 600
        //        M2a：4 个 LONGLONG(32) + UCHAR[8] + 2 个 LONGLONG(16) = 56 → 656
        assert_eq!(std::mem::size_of::<DriverStats>(), 656, "与驱动 OUG_STATS 不一致");
    }

    #[test]
    fn rules_layout_matches_driver() {
        // 4+4 + 16*260*2 + 4 + 32*16*2 = 9356
        assert_eq!(std::mem::size_of::<DriverRules>(), 9356, "与驱动 OUG_RULES 不一致");
    }

    #[test]
    fn rules_serialization_roundtrip() {
        let rules = DriverRules::new(
            42,
            &["\\Device\\HarddiskVolume3\\机密".to_string()],
            &[".docx".to_string(), ".xlsx".to_string()],
        )
        .expect("构造成功");
        assert_eq!(rules.version, 42);
        assert_eq!(rules.path_prefix_count, 1);
        assert_eq!(rules.ext_count, 2);
        let first_ext: String = rules.extensions[0]
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(first_ext, ".docx");
    }

    #[test]
    fn rules_reject_oversized_values() {
        let long_ext = ".".to_string() + &"a".repeat(MAX_EXT_LEN);
        assert!(DriverRules::new(1, &[], &[long_ext]).is_err());
        assert!(DriverRules::new(1, &vec!["x".to_string(); MAX_PREFIXES + 1], &[]).is_err());
    }

    #[test]
    fn dos_path_requires_drive_letter() {
        assert!(dos_to_nt_path(Path::new("relative\\path")).is_err());
        assert!(dos_to_nt_path(Path::new("\\\\server\\share")).is_err());
    }
}
