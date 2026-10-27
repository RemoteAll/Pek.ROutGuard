//! 服务端运行时状态（配置快照 / 主密钥 / 数据库 / 面板会话）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use dhrust::net::login_guard::LoginGuard;
use dhrust::net::panel_auth::TokenStore;
use pek_outguard_core::crypto;
use pek_rcode::store::SharedStore;

use crate::config::{self, ServerSection};
use crate::db;
use crate::keys;

/// 面板会话（令牌 → 身份）。
#[derive(Debug, Clone)]
pub struct PanelSession {
    /// 用户名
    pub user: String,
    /// 是否内置管理员（配置文件账号）
    pub builtin: bool,
}

/// 服务端运行时。
pub struct App {
    /// 程序基目录
    pub base: PathBuf,
    /// 配置快照（面板改配置后热更新）
    pub server: RwLock<ServerSection>,
    /// 主密钥
    pub master: [u8; crypto::KEY_LEN],
    /// 数据库共享存储
    pub store: Arc<SharedStore>,
    /// 进程启动时间
    pub started: Instant,
    /// 登录限流（15 分钟 5 次，封 5 分钟）
    pub login_guard: LoginGuard,
    /// 面板令牌（12 小时滑动续期）
    pub tokens: TokenStore<PanelSession>,
    /// 客户端 nonce 缓存（防重放；unix 秒 → 首次见到时间）
    pub nonces: Mutex<HashMap<String, i64>>,
}

impl App {
    /// 打开服务端（配置 → 主密钥 → 数据库）。
    pub fn open(base: &Path) -> Result<Arc<App>, String> {
        std::fs::create_dir_all(base).map_err(|e| format!("创建程序目录失败：{e}"))?;
        let config = config::load(base);
        let server = config.value().server.clone();

        let (master, created) = keys::load_or_create(base)?;
        if created {
            dhrust::warn!(
                "已生成主密钥：{} —— 请立即备份；丢失将导致所有加密文件无法解密",
                keys::key_path(base).display()
            );
        }

        let store = db::open(base)?;
        if let Err(e) = db::ensure_default_policy(&store) {
            dhrust::warn!("默认规则集初始化失败：{e}");
        }
        let app = Arc::new(App {
            base: base.to_path_buf(),
            server: RwLock::new(server),
            master,
            store,
            started: Instant::now(),
            login_guard: LoginGuard::new(),
            tokens: TokenStore::with_ttl_ms(12 * 60 * 60 * 1000),
            nonces: Mutex::new(HashMap::new()),
        });
        if let Err(e) = sync_config_fingerprint(&app) {
            dhrust::warn!("配置指纹比对失败（配置变更可能不会下发）：{e}");
        }
        Ok(app)
    }

    /// 配置快照。
    pub fn server(&self) -> ServerSection {
        self.server
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// 首次启动：面板密码为空时初始化为 admin/admin，并尽量写回配置文件。
    ///
    /// 返回值 `true` 表示本次初始化（调用方应提示改密）。
    pub fn ensure_default_account(&self) -> Result<bool, String> {
        let (user, stored) = {
            let mut guard = self
                .server
                .write()
                .map_err(|_| "配置锁被污染".to_string())?;
            if !guard.web_password_hash.is_empty() {
                return Ok(false);
            }
            let salt = dhrust::random::hex(8);
            let hash = config::hash_password(&salt, "admin");
            let stored = format!("{salt}:{hash}");
            guard.web_password_hash = stored.clone();
            (guard.web_user_name.clone(), stored)
        };

        let path = config::config_path(&self.base);
        if let Ok(text) = std::fs::read_to_string(&path) {
            let updated = text.replace(
                "WebPasswordHash = \"\"",
                &format!("WebPasswordHash = \"{stored}\""),
            );
            if updated != text
                && let Err(e) = std::fs::write(&path, updated)
            {
                dhrust::warn!("默认面板密码未能写回配置：{e}");
            }
        }
        dhrust::warn!("面板账号已初始化为 {user}/admin —— 请尽快在配置中改密");
        Ok(true)
    }

    /// 校验面板账号（内置管理员）。
    pub fn verify_login(&self, user: &str, password: &str) -> Option<PanelSession> {
        let server = self.server();
        if user == server.web_user_name && config::verify_password(&server.web_password_hash, password)
        {
            Some(PanelSession {
                user: user.to_string(),
                builtin: true,
            })
        } else {
            None
        }
    }

    /// 运行时长（秒）。
    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

/// 服务端配置指纹：只覆盖**会下发给客户端**的字段。
///
/// 这些字段不在"规则 JSON"里，`save_policy` 的比较看不出变化、版本不会涨，
/// 客户端心跳便永远认为"策略没变"——配置改了不下发。所以启动时比对指纹：
/// 变化就 `bump_all_policies` 推一版，让客户端重新拉取。
fn config_fingerprint(server: &ServerSection) -> String {
    let payload = format!(
        "company={}|notice={}|class={}|roots={}|exclude={}|uninstall={}|grace={}|auto={}",
        server.company_name,
        server.notice,
        server.classification,
        server.watch_roots.join(","),
        server.exclude_paths.join(","),
        server.allow_uninstall,
        server.offline_grace_days,
        server.auto_approve,
    );
    pek_outguard_core::crypto::hex(&pek_outguard_core::crypto::sha256(payload.as_bytes()))
}

const FINGERPRINT_KEY: &str = "config.fingerprint";

/// 比对并（必要时）提升规则集版本。
fn sync_config_fingerprint(app: &App) -> Result<(), String> {
    let server = app.server();
    let fingerprint = config_fingerprint(&server);
    let stored = db::get_setting(&app.store, FINGERPRINT_KEY)?;
    match stored {
        Some(old) if old == fingerprint => Ok(()),
        Some(old) => {
            let version = db::bump_all_policies(&app.store)?;
            dhrust::info!(
                "服务端配置已变更（{} → {}），规则集版本提升到 v{version}，客户端将重新同步",
                &old[..old.len().min(12)],
                &fingerprint[..12]
            );
            db::set_setting(&app.store, FINGERPRINT_KEY, &fingerprint)
        }
        // 首次启动：只记指纹，不升版本（避免刚装机就把版本推高一版）。
        None => {
            db::set_setting(&app.store, FINGERPRINT_KEY, &fingerprint)?;
            dhrust::info!("已记录服务端配置指纹：{}", &fingerprint[..12]);
            Ok(())
        }
    }
}
