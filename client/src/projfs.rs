//! 透明加密视图（Windows 投影文件系统 ProjFS）。
//!
//! **目标（用户要求"无感"）**：用户在一个"安全区"目录里看到的是**普通文件名**
//! （`合同.docx`），Word/WPS 直接打开、直接保存，全程不知道文件其实是密文；
//! 只有在没装客户端、或把文件拷走时才打不开。
//!
//! **为什么是 ProjFS 而不是驱动**：
//! - `ProjectedFSLib.dll` 是 Windows 10 1809+ / Server 2019+ **系统内置**的用户态组件；
//! - 不需要 WDK、不需要代码签名、不会蓝屏、不与其他安全软件抢文件系统过滤栈；
//! - 代价：只对**安全区目录**生效（不是全盘透明），并且无法阻止已登录用户把明文复制出去
//!   （这部分由文件监控兜底：复制到受控外的落点会被自动加密）。
//!
//! **工作原理**：
//! 1. 安全区目录（`.ogd` 存储区）里只有密文；
//! 2. 把安全区映射成一个 virtualization root，文件系统枚举/读取时回调本模块；
//! 3. 读取 → 解密交给调用方；写入 → 加密落盘。
//!
//! 本文件当前是**技术验证骨架**：先确认 ProjFS API 可用与调用方式，后续补齐回调实现。

#![cfg(windows)]

use std::path::Path;

/// ProjFS 是否可用（系统是否带 `ProjectedFSLib.dll` 且版本满足）。
pub fn is_supported() -> bool {
    dll_path().is_some()
}

fn dll_path() -> Option<std::path::PathBuf> {
    let system_root = std::env::var_os("SystemRoot")?;
    let path = Path::new(&system_root)
        .join("System32")
        .join("ProjectedFSLib.dll");
    path.is_file().then_some(path)
}

/// 探测结果（用于 `status` 与安装自检）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// 系统是否提供 ProjFS
    pub supported: bool,
    /// `ProjectedFSLib.dll` 路径
    pub dll: Option<String>,
    /// 虚拟化能力说明（给运维看的一句话）
    pub detail: String,
}

/// 探测本机 ProjFS 支持情况。
pub fn probe() -> Probe {
    match dll_path() {
        Some(path) => Probe {
            supported: true,
            dll: Some(path.display().to_string()),
            detail: "支持透明加密视图（ProjFS，纯用户态）".to_string(),
        },
        None => Probe {
            supported: false,
            dll: None,
            detail: "系统未提供 ProjectedFSLib.dll（需 Windows 10 1809+ / Server 2019+）；\
                     将退回「受控打开」模式（双击 .ogd 由客户端解密后交给 Office）"
                .to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_dll_presence() {
        let probe = probe();
        // 只要结果自洽：supported 与 dll 同时存在或同时缺失。
        assert_eq!(probe.supported, probe.dll.is_some());
        if probe.supported {
            assert!(probe.detail.contains("ProjFS"));
        } else {
            assert!(probe.detail.contains("受控打开"));
        }
    }
}
