//! `.ogd` 文件关联（`HKCU`，无需管理员）：**双击加密文件直接由客户端受控打开**。
//!
//! 解决的是"每打开一个文件都要先敲一遍 decrypt"的体验问题：
//! 关联后用户双击 `合同.docx.ogd` 即走 [`crate::opensession`] 的受控打开闭环，
//! 感知上只多"等一下打开"的时间，不需要知道解密这一步存在。
//!
//! **不做的事（边界如实写清）**：
//! - 不做 Shell 扩展 DLL（Win10 `IContextMenu` 与 Win11 新菜单机制不同、易被杀软拦截），
//!   右键菜单用注册表静态动词实现；
//! - 不做进程注入 / 文件系统过滤：Office 内「文件 → 打开」对话框里看到的仍是 `.ogd`，
//!   要"Word 里直接打开原文件名"必须靠 ProjFS 虚拟目录或内核 minifilter（见
//!   `docs/架构设计.md` 的「透明打开路线」）。
//!
//! 注册位置全部在 `HKCU\Software\Classes` → 只影响执行 `install` 的那个用户，不需要提权。

use std::path::Path;

/// 自定义 ProgID（用固定名避免与其它软件冲突）。
pub const PROG_ID: &str = "PekROutGuard.EncryptedFile";
/// 文件类型描述。
pub const TYPE_NAME: &str = "OutGuard 加密文件";

/// 是否 Windows（其它平台暂时不注册关联）。
pub fn is_supported() -> bool {
    cfg!(windows)
}

/// 注册 `.ogd` 关联（幂等）。
///
/// `exe` 传当前可执行文件路径；写入的打开命令为 `"<exe>" open "%1"`。
pub fn register(exe: &Path) -> Result<(), String> {
    if !is_supported() {
        return Err("当前平台暂不支持自动注册文件关联（仅 Windows）".into());
    }
    let exe = exe
        .to_str()
        .ok_or_else(|| format!("可执行文件路径含非法字符：{}", exe.display()))?;
    let command = format!("\"{exe}\" open \"%1\"");

    let classes = r"HKCU\Software\Classes";
    set(&format!(r"{classes}\.ogd"), "", PROG_ID)?;
    set(&format!(r"{classes}\{PROG_ID}"), "", TYPE_NAME)?;
    set(
        &format!(r"{classes}\{PROG_ID}\DefaultIcon"),
        "",
        &format!("\"{exe}\",0"),
    )?;
    set(
        &format!(r"{classes}\{PROG_ID}\shell\open\command"),
        "",
        &command,
    )?;
    // Windows 11 的「打开方式」列表靠 Applications + OpenWithProgids 才稳定出现。
    set(
        &format!(r"{classes}\{PROG_ID}\shell\open"),
        "FriendlyAppName",
        "OutGuard",
    )?;
    set(
        &format!(r"{classes}\.ogd\OpenWithProgids"),
        PROG_ID,
        "",
    )?;
    dhrust::info!("已注册文件关联：.ogd → {command}");
    Ok(())
}

/// 解除关联（幂等；卸载时调用）。
///
/// 只在 `.ogd` 确实指向本程序的 ProgID 时才删除该键——避免误删其它软件设置的关联。
pub fn unregister() -> Result<(), String> {
    if !is_supported() {
        return Ok(());
    }
    let classes = r"HKCU\Software\Classes";
    let mut errors = Vec::new();
    if query_default(&format!(r"{classes}\.ogd")).as_deref() == Some(PROG_ID)
        && let Err(e) = delete_tree(&format!(r"{classes}\.ogd"))
    {
        errors.push(e);
    }
    if let Err(e) = delete_tree(&format!(r"{classes}\{PROG_ID}")) {
        errors.push(e);
    }
    if errors.is_empty() {
        dhrust::info!("已解除 .ogd 文件关联");
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

/// 当前关联到的命令行（未注册返回 `None`）。
pub fn query() -> Option<String> {
    if !is_supported() {
        return None;
    }
    query_default(&format!(r"HKCU\Software\Classes\{PROG_ID}\shell\open\command"))
}

/// 查询某个键的默认值（键/值不存在返回 `None`）。
fn query_default(key: &str) -> Option<String> {
    let output = std::process::Command::new("reg")
        .args(["query", key, "/ve"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // 输出形如：`    (默认)    REG_SZ    "C:\...\pek-outguard-client.exe" open "%1"`
    text.lines()
        .find(|line| line.contains("REG_SZ"))
        .and_then(|line| line.split("REG_SZ").nth(1))
        .map(|value| value.trim().to_string())
}

fn set(key: &str, name: &str, value: &str) -> Result<(), String> {
    let mut command = std::process::Command::new("reg");
    command.args(["add", key]);
    if name.is_empty() {
        command.args(["/ve"]);
    } else {
        command.args(["/v", name]);
    }
    command.args(["/t", "REG_SZ", "/d", value, "/f"]);
    run(command, &format!("写入注册表 {key}"))
}

fn delete_tree(key: &str) -> Result<(), String> {
    let command = {
        let mut command = std::process::Command::new("reg");
        command.args(["delete", key, "/f"]);
        command
    };
    // 键不存在视为成功（幂等卸载）。
    match run_raw(command) {
        Ok(output) => {
            if output.status.success() {
                Ok(())
            } else {
                let text = String::from_utf8_lossy(&output.stderr);
                if text.contains("找不到") || text.to_ascii_lowercase().contains("unable to find")
                {
                    Ok(())
                } else {
                    Err(format!("删除注册表 {key} 失败：{}", text.trim()))
                }
            }
        }
        Err(e) => Err(e),
    }
}

fn run(command: std::process::Command, what: &str) -> Result<(), String> {
    let output = run_raw(command)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what}失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_raw(mut command: std::process::Command) -> Result<std::process::Output, String> {
    command
        .output()
        .map_err(|e| format!("调用 reg.exe 失败：{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prog_id_is_stable() {
        // 改这个值会影响已部署机器的关联，必须保持稳定。
        assert_eq!(PROG_ID, "PekROutGuard.EncryptedFile");
    }

    #[test]
    fn register_and_query_roundtrip() {
        if !is_supported() {
            return;
        }
        // 只在测试机注册自己的关联（HKCU，幂等，测试后还原）。
        let exe = std::path::PathBuf::from("C:\\Test\\pek-outguard-client.exe");
        let before = query();
        register(&exe).expect("注册关联");
        let command = query().expect("应能查到关联");
        assert!(command.contains("pek-outguard-client.exe"), "{command}");
        assert!(command.contains("open"), "{command}");
        // 还原：先前没有就删掉，有就保持（测试机干净）。
        if before.is_none() {
            let _ = unregister();
        }
    }
}
