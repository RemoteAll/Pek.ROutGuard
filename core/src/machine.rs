//! 设备唯一码（MachineId）与基础数据归一化。
//!
//! 客户端在 Windows 上采集三样东西（本模块只做组合与哈希，采集由客户端实现）：
//! 1. **SMBIOS UUID**（主板出厂 UUID；重装系统不变，最稳定）
//! 2. **MachineGuid**（`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`；重装会变，作兜底）
//! 3. **系统盘卷序列号**（`GetVolumeInformationW`；格式化会变，作补充）
//!
//! 组合后取 SHA-256 前 128 位作为机器码：
//! `machine_id = hex(SHA-256("outguard|uuid|guid|volume"))[..32]`
//!
//! **已知限制**：虚拟机批量克隆会得到相同 UUID → 面板应提示"疑似克隆"，由管理员人工绑定；
//! 不做"安装时随机盐"，否则重装后无法识别同一台机器。

use crate::crypto;
use crate::error::{Error, Result};

/// 机器码长度（十六进制字符数，128 位足够防碰撞）。
pub const MACHINE_ID_LEN: usize = 32;

/// 生成设备唯一码；三者全空时报错（调用方应至少采集到一项）。
pub fn machine_id(smbios_uuid: &str, machine_guid: &str, volume_serial: &str) -> Result<String> {
    let parts = [
        normalize_part(smbios_uuid),
        normalize_part(machine_guid),
        normalize_part(volume_serial),
    ];
    if parts.iter().all(|part| part.is_empty()) {
        return Err(Error::Protocol(
            "无法生成机器码：SMBIOS UUID / MachineGuid / 卷序列号均为空".into(),
        ));
    }

    let material = format!("outguard|{}|{}|{}", parts[0], parts[1], parts[2]);
    let hash = crypto::sha256(material.as_bytes());
    Ok(crypto::hex(&hash)[..MACHINE_ID_LEN].to_string())
}

/// 归一化单个标识：去空白、连字符、大括号，转小写。
///
/// 这样 `{4C4C4544-...}`、`4c4c4544...`、`4C4C4544 - ...` 会得到同一结果。
pub fn normalize_part(raw: &str) -> String {
    raw.chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-' && *ch != '{' && *ch != '}')
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "4C4C4544-0038-4B10-8051-CAC04F4D4E31";
    const GUID: &str = "3f2a8c1e-9b7d-4e6f-8a2b-1c3d5e7f9a0b";
    const VOLUME: &str = "A4C3-19F2";

    #[test]
    fn stable_for_same_input() {
        let a = machine_id(UUID, GUID, VOLUME).expect("生成成功");
        let b = machine_id(UUID, GUID, VOLUME).expect("生成成功");
        assert_eq!(a, b);
        assert_eq!(a.len(), MACHINE_ID_LEN);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn normalizes_format_differences() {
        let plain = machine_id(UUID, GUID, VOLUME).expect("生成成功");
        let formatted = machine_id(
            &format!("{{{}}}", UUID.to_ascii_lowercase()),
            &GUID.replace('-', " - "),
            &VOLUME.to_ascii_lowercase(),
        )
        .expect("生成成功");
        assert_eq!(plain, formatted, "大小写/大括号/连字符差异不得改变机器码");
    }

    #[test]
    fn different_machine_differs() {
        let a = machine_id(UUID, GUID, VOLUME).expect("生成成功");
        let b = machine_id(UUID, GUID, "B5D4-2AF3").expect("生成成功");
        assert_ne!(a, b);
    }

    #[test]
    fn falls_back_to_single_component() {
        // 只采到 MachineGuid（读不到 SMBIOS）也能生成，保证可用性。
        let id = machine_id("", GUID, "").expect("生成成功");
        assert_eq!(id.len(), MACHINE_ID_LEN);
    }

    #[test]
    fn rejects_all_empty() {
        assert!(machine_id("", "  ", "{}").is_err());
    }

    #[test]
    fn normalize_part_cases() {
        assert_eq!(normalize_part(" {4C4C-4544} "), "4c4c4544");
        assert_eq!(normalize_part(""), "");
    }
}
