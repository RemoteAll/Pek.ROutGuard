//! 服务化：把客户端注册为系统服务（Windows SCM / systemd），并设置失败自动恢复。
//!
//! **防退出（第一层）**：
//! - 服务以 LocalSystem 运行，普通用户无法结束或停止（Windows 默认只有管理员可停）；
//! - 失败恢复策略：崩溃 5s / 10s / 30s 三次重启，之后每天重置计数；
//! - **卸载需要服务端授权**（`AllowUninstall`，默认 false），由 `uninstall` 命令校验。
//!
//! 边界（如实说明）：本地管理员仍可通过系统工具停止/删除服务——用户态方案不对抗管理员。

use std::path::Path;

use dhrust::service::{ServiceManager, ServiceState};

/// 服务名（注册表 / SCM 里显示）。
pub const SERVICE_NAME: &str = "PekROutGuardClient";
/// 显示名。
pub const DISPLAY_NAME: &str = "Pek ROutGuard Client";
/// 描述。
pub const DESCRIPTION: &str = "企业文件防泄漏终端（自动加密/受控打开；不可随意停止或卸载）";

/// 装配服务管理器。
pub fn manager(base: &Path) -> ServiceManager {
    ServiceManager::new(base, SERVICE_NAME, DISPLAY_NAME, DESCRIPTION, &[])
}

/// 安装服务（可选立即启动）+ 设置失败恢复策略。
pub fn install(base: &Path, start: bool) -> Result<(), String> {
    let manager = manager(base);
    manager.install(false)?;
    apply_recovery(SERVICE_NAME);
    if start {
        manager.start()?;
    }
    dhrust::info!("客户端服务已安装：{SERVICE_NAME}（start={start}）");
    Ok(())
}

/// 卸载服务（先停止）。
pub fn uninstall(base: &Path) -> Result<(), String> {
    manager(base).uninstall(true)
}

/// 查询服务状态。
pub fn query(base: &Path) -> ServiceState {
    manager(base).query()
}

/// 设置 Windows 失败恢复策略（非 Windows 平台为空操作）。
fn apply_recovery(name: &str) {
    #[cfg(windows)]
    {
        let outcome = std::process::Command::new("sc")
            .args([
                "failure",
                name,
                "reset=",
                "86400",
                "actions=",
                "restart/5000/restart/10000/restart/30000",
            ])
            .status();
        match outcome {
            Ok(status) if status.success() => {
                dhrust::info!("服务失败恢复策略已设置：{name}（5s/10s/30s 重启）")
            }
            other => dhrust::warn!("服务失败恢复策略设置失败：{other:?}"),
        }
    }
    #[cfg(not(windows))]
    let _ = name;
}
