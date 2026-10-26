//! 文件监控：`notify`（Windows ReadDirectoryChangesW / Linux inotify）+ 去抖 + 单工作线程。
//!
//! 资源口径（用户级"资源与带宽"约定）：
//! - **只监控策略下发的 `watch_roots`**，不做周期性全盘扫描；
//! - 变化去抖 800 ms（Office 保存会连续产生多个写事件）；
//! - 单工作线程顺序处理，避免并发加密同一文件；事件映射只在内存，不落盘。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

/// 监控句柄（drop 即停止底层 watcher）。
pub struct WatchHandle {
    /// 实际生效的监控根路径
    pub roots: Vec<PathBuf>,
    _watcher: RecommendedWatcher,
}

/// 启动监控：变化去抖 `debounce` 后交给单工作线程处理。
pub fn start<F>(roots: Vec<PathBuf>, debounce: Duration, handler: F) -> Result<WatchHandle, String>
where
    F: Fn(PathBuf) + Send + 'static,
{
    if roots.is_empty() {
        return Err("监控根为空".into());
    }

    let (events_tx, events_rx) = channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(move |result| {
        let _ = events_tx.send(result);
    })
    .map_err(|e| format!("创建监控器失败：{e}"))?;

    let mut watched = Vec::new();
    for root in roots {
        match watcher.watch(&root, RecursiveMode::Recursive) {
            Ok(()) => watched.push(root),
            Err(e) => dhrust::warn!("监控路径失败（{}）：{e}", root.display()),
        }
    }
    if watched.is_empty() {
        return Err("没有可监控的路径（检查 WatchRoots 是否存在）".into());
    }

    let pending: Arc<Mutex<HashMap<PathBuf, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    // 事件收集：只记录创建/修改，按路径覆盖时间戳（同一文件多次写入只保留最新）。
    {
        let pending = Arc::clone(&pending);
        std::thread::spawn(move || {
            for result in events_rx {
                let Ok(event) = result else { continue };
                if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    continue;
                }
                let Ok(mut map) = pending.lock() else { continue };
                for path in event.paths {
                    map.insert(path, Instant::now());
                }
            }
        });
    }

    // 去抖 → 有界处理队列（单工作线程顺序执行）。
    let (work_tx, work_rx) = channel::<PathBuf>();
    {
        let pending = Arc::clone(&pending);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(300));
                let mut due = Vec::new();
                {
                    let Ok(mut map) = pending.lock() else { return };
                    let now = Instant::now();
                    map.retain(|path, at| {
                        if now.duration_since(*at) >= debounce {
                            due.push(path.clone());
                            false
                        } else {
                            true
                        }
                    });
                }
                for path in due {
                    if work_tx.send(path).is_err() {
                        return;
                    }
                }
            }
        });
    }
    std::thread::spawn(move || {
        for path in work_rx {
            handler(path);
        }
    });

    dhrust::info!(
        "文件监控已启动：{} 个根路径，去抖 {} ms",
        watched.len(),
        debounce.as_millis()
    );
    Ok(WatchHandle {
        roots: watched,
        _watcher: watcher,
    })
}

/// 跳过容器自身与临时文件（避免"加密产生的密文再次被加密"）。
pub fn should_skip(path: &std::path::Path) -> bool {
    let text = path.to_string_lossy().to_ascii_lowercase();
    text.ends_with(".ogd") || text.ends_with(".tmp") || text.contains("\\outguard\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_rules() {
        assert!(should_skip(std::path::Path::new("D:\\Work\\a.docx.ogd")));
        assert!(should_skip(std::path::Path::new("D:\\Work\\a.docx.tmp")));
        assert!(should_skip(std::path::Path::new(
            "C:\\ProgramData\\Pek\\OutGuard\\temp\\a.docx"
        )));
        assert!(!should_skip(std::path::Path::new("D:\\Work\\a.docx")));
    }
}
