//! 安全区：ProjFS 透明加密目录（**用户看到普通文件名，读写在回调里解密/加密**）。
//!
//! # 为什么
//!
//! 用户要求"不要双击 .ogd，要像普通文件一样用"。纯用户态唯一能做到的路：
//! Windows 10 1809+/Server 2019+ 内置的**投影文件系统（ProjFS）**——
//! 不需要驱动、不需要代码签名、不会蓝屏。
//!
//! # 形态
//!
//! ```text
//!  安全区（用户看到的虚拟目录）：  D:\SecureWork\采购合同.docx      ← 普通文件名，Word 直接开
//!  密文库（真实文件）：            <Data>\Vault\采购合同.docx.ogd   ← 磁盘上只有密文
//! ```
//!
//! 目录枚举/读取走 ProjFS 回调（本模块解密后交给系统）；
//! 写入由 ProjFS 落成本地实体文件，随后由文件监控（`runtime`）加密搬进密文库、
//! 删除实体并重建 placeholder——所以**用户保存后磁盘上仍是密文**。
//!
//! # 边界（如实写清）
//!
//! - 只对**显式配置的安全区**生效，不是全盘透明；
//! - 本机已登录进程读到的是明文（这正是"无感"的含义），
//!   "拷走打不开"靠文件监控在落点再加密；
//! - 安全区目录必须是**空目录**（ProjFS 要求），已有文件需先导入密文库。

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Storage::ProjectedFileSystem::{
    PRJ_CALLBACKS, PRJ_CALLBACK_DATA, PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO,
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT, PRJ_PLACEHOLDER_INFO, PRJ_PLACEHOLDER_VERSION_INFO,
    PRJ_STARTVIRTUALIZING_OPTIONS, PRJ_VIRTUALIZATION_INSTANCE_INFO,
};

// ————— 手写 FFI（windows-sys 只导出类型，不导出 ProjFS 函数）—————

const S_OK: i32 = 0;
const E_FAIL: i32 = 0x8000_4005u32 as i32;
const HR_FILE_NOT_FOUND: i32 = 0x8007_0002u32 as i32;

/// `PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN`
const ENUM_RESTART_SCAN: i32 = 0x0000_0001;
/// `PRJ_UPDATE_ALLOW_DIRTY_METADATA`
const UPDATE_ALLOW_DIRTY_METADATA: i32 = 0x0000_0001;
/// `PRJ_UPDATE_ALLOW_DIRTY_DATA`
const UPDATE_ALLOW_DIRTY_DATA: i32 = 0x0000_0002;

/// 容器扩展名（密文库内的文件）。
const VAULT_EXT: &str = "ogd";

#[link(name = "ProjectedFSLib")]
unsafe extern "system" {
    /// 把目录标记为虚拟化根（文档要求：`PrjStartVirtualizing` 前必须先调一次）。
    fn PrjMarkDirectoryAsPlaceholder(
        root_path_name: *const u16,
        target_path_name: *const u16,
        version_info: *const PRJ_PLACEHOLDER_VERSION_INFO,
        virtualization_instance_id: *const windows_sys::core::GUID,
    ) -> i32;

    fn PrjStartVirtualizing(
        virtualization_root_path: *const u16,
        callbacks: *const PRJ_CALLBACKS,
        instance_context: *const c_void,
        options: *const PRJ_STARTVIRTUALIZING_OPTIONS,
        namespace_virtualization_context: *mut PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    ) -> i32;

    fn PrjStopVirtualizing(namespace_virtualization_context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT);

    fn PrjWritePlaceholderInfo(
        namespace_virtualization_context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
        destination_file_name: *const u16,
        placeholder_info: *const PRJ_PLACEHOLDER_INFO,
        placeholder_info_size: u32,
    ) -> i32;

    fn PrjWriteFileData(
        namespace_virtualization_context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
        data_stream_id: *const windows_sys::core::GUID,
        buffer: *const c_void,
        byte_offset: u64,
        length: u32,
    ) -> i32;

    fn PrjFillDirEntryBuffer(
        file_name: *const u16,
        file_basic_info: *const PRJ_FILE_BASIC_INFO,
        dir_entry_buffer_handle: PRJ_DIR_ENTRY_BUFFER_HANDLE,
    ) -> i32;

    fn PrjGetVirtualizationInstanceInfo(
        namespace_virtualization_context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
        virtualization_instance_info: *mut PRJ_VIRTUALIZATION_INSTANCE_INFO,
    ) -> i32;

    /// 把“已被修改的占位符（实体文件）”抷回占位符（可按 flags 丢弃本地数据）。
    fn PrjUpdateFileIfNeeded(
        namespace_virtualization_context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
        destination_file_name: *const u16,
        placeholder_info: *const PRJ_PLACEHOLDER_INFO,
        placeholder_info_size: u32,
        update_flags: i32,
        failure_reason: *mut i32,
    ) -> i32;
}

// ————— 对外接口 —————

/// 按容器头里的 `policyId` 解析策略密钥。
pub type KeyResolver = dyn Fn(&str) -> Option<[u8; 32]> + Send + Sync;

/// 安全区审计回调：`(动作, 相对路径, 大小)`。
///
/// 动作：`"open"`（用户打开读） / `"seal"`（保存后重新加密） / `"import"`（导入）。
pub type AuditSink = dyn Fn(&'static str, &str, Option<u64>) + Send + Sync;

/// 安全区启动参数。
#[derive(Clone)]
pub struct SecureAreaOptions {
    /// 虚拟根（用户看到的目录；**必须是空目录**）
    pub root: PathBuf,
    /// 密文库（`.ogd` 按相对路径存放）
    pub vault: PathBuf,
    /// 解密缓存（避免每次读都全量解密；容器变更即失效）
    pub cache: PathBuf,
    /// 新文件加密用的规则集 ID
    pub policy_id: String,
    /// 公司名称（写入容器明文头）
    pub company: String,
    /// 防泄密提示语（写入容器明文头）
    pub notice: String,
    /// 密级
    pub classification: String,
    /// 审计回调（可选）
    pub audit: Option<Arc<AuditSink>>,
}

/// 运行中的安全区（drop 即停止虚拟化）。
pub struct SecureArea {
    context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    inner: *const Inner,
    /// 给外部做日志/状态用
    pub options: SecureAreaOptions,
}

// ProjFS 上下文句柄本身是线程安全的（内核对象），这里只需要把它交回 Stop。
unsafe impl Send for SecureArea {}
// 内部可变状态都在 Mutex 里；context 是内核句柄。
unsafe impl Sync for SecureArea {}

impl SecureArea {
    /// 全量清扫安全区里的实体明文（启动兜底/手工触发），返回处理数。
    ///
    /// **正常运行不走这里**——文件监控会精准告诉自己哪个文件变了（见 [`Self::seal_path`]）。
    pub fn seal_dirty(&self) -> usize {
        let mut sealed = 0usize;
        let mut stack = vec![self.options.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = entry.metadata() else { continue };
                if meta.is_dir() {
                    stack.push(path);
                    continue;
                }
                if is_placeholder(&meta) {
                    continue;
                }
                // 启动清扫必须“扫到就处理完”，不能沿用 seal_path 的时间窗跳过。
                match self.seal_one(unsafe { &*self.inner }, &path, true) {
                    Ok(()) => sealed += 1,
                    Err(e) => dhrust::warn!(
                        "启动清扫加密失败（{}）：{e}（明文已保留，稍后重试）",
                        path.display()
                    ),
                }
            }
        }
        if sealed > 0 {
            dhrust::info!("安全区已加密 {sealed} 个改动文件（磁盘上只留密文）");
        }
        sealed
    }

    /// 处理**单个**文件的落盘加密（精准路径，不全盘扫描）。
    ///
    /// 返回 `true` 表示确实做了加密；占位符、目录、失效路径、刚看过的同一版本文件返回 `false`。
    pub fn seal_path(&self, path: &Path) -> bool {
        let inner = unsafe { &*self.inner };
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        if meta.is_dir() || is_placeholder(&meta) {
            return false;
        }
        let relative = path
            .strip_prefix(&self.options.root)
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        // 打开文件（hydrate）也会产生 Modify 事件；大小和 mtime 都没变时
        // 不可能有新内容，直接跳过——否则读 300 MB 要白算十几次哈希。
        if !relative.is_empty()
            && let Ok(mut recent) = inner.recent.lock()
        {
            if let Some((size, at, stamp)) = recent.get(&relative)
                && *size == meta.len()
                && *at == mtime
                && stamp.elapsed() < std::time::Duration::from_secs(5)
            {
                return false;
            }
            if recent.len() > 4000 {
                recent.clear();
            }
            recent.insert(
                relative.clone(),
                (meta.len(), mtime, std::time::Instant::now()),
            );
        }
        match self.seal_one(inner, path, false) {
            Ok(()) => true,
            Err(e) => {
                dhrust::warn!("安全区落盘加密失败（{}）：{e}", path.display());
                false
            }
        }
    }

    /// 把**已水化（磁盘上已有明文）且已经空闲**的文件降级回占位符。
    ///
    /// ProjFS 的 hydrate 会在本地留下真实数据；应用关掉文件后这些明文没必要留着。
    /// 这里只处理"自己读过的文件"（内存表，几 KB），**不扫目录**。
    /// 返回处理的文件数。
    ///
    /// 关键：**绝不丢用户改动**——走的仍是 [`Self::seal_one`]，
    /// 内容与密文库一致才纯降级，不一致会先加密落库再降级。
    pub fn dehydrate_idle(&self, idle: std::time::Duration) -> usize {
        let inner = unsafe { &*self.inner };
        let due: Vec<String> = {
            let Ok(mut hydrated) = inner.hydrated.lock() else {
                return 0;
            };
            let now = std::time::Instant::now();
            let mut due = Vec::new();
            hydrated.retain(|relative, at| {
                if now.duration_since(*at) >= idle {
                    due.push(relative.clone());
                    false
                } else {
                    true
                }
            });
            due
        };
        let mut count = 0usize;
        for relative in due {
            let path = self.options.root.join(&relative);
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if meta.is_dir() || is_placeholder(&meta) {
                continue;
            }
            match self.seal_one(inner, &path, true) {
                Ok(()) => {
                    count += 1;
                    // seal_one 成功后 hydrated 已被清掉，这里无需再动。
                }
                Err(e) => {
                    // 失败就把文件重新放回队列，下个周期再试（不丢改动）。
                    dhrust::warn!("空闲脱水失败（{relative}）：{e}（稍后重试）");
                    if let Ok(mut hydrated) = inner.hydrated.lock() {
                        hydrated.insert(relative, std::time::Instant::now());
                    }
                }
            }
        }
        count
    }

    fn seal_one(&self, inner: &Inner, path: &Path, demote_clean: bool) -> Result<(), String> {
        let relative = path
            .strip_prefix(&self.options.root)
            .map_err(|e| format!("计算相对路径失败：{e}"))?
            .to_string_lossy()
            .to_string();
        if relative.is_empty() || relative.starts_with('.') {
            return Ok(());
        }
        let key = (inner.key)(&self.options.policy_id)
            .ok_or_else(|| format!("策略密钥不可用（policyId={}）", self.options.policy_id))?;
        let meta = std::fs::metadata(path).map_err(|e| format!("读取实体文件信息失败：{e}"))?;
        let plain_size = meta.len();
        // 流式哈希：几百 MB 的 CAD 也只用一个 256 KB 缓冲，不会把进程撑爆。
        let plain_hash =
            pek_outguard_core::crypto::sha256_file(path).map_err(|e| format!("计算明文哈希失败：{e}"))?;
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();

        // ProjFS 的 hydrate（用户打开文件）也会触发 Modify，导致同内容反复“落盘加密”。
        // 去重不能只靠内存表（服务重启就空了）——**以密文库容器头里的 plainSha256 为准**，
        // 这样“打开→浏览→关闭”全程不会重写密文，只有内容真的变了才重新加密。
        let vault_path = inner.vault_path(&relative);
        let known_hash = inner
            .sealed
            .lock()
            .ok()
            .and_then(|map| map.get(&relative).copied());
        let unchanged = match known_hash {
            Some(hash) => hash == plain_hash,
            None => {
                container_plain_hash(&vault_path)
                    == Some(pek_outguard_core::crypto::hex(&plain_hash))
            }
        };
        if unchanged {
            if demote_clean {
                demote_to_placeholder(self.context, &relative, path, plain_size as i64)?;
            } else {
                // **不在水化时立刻降级**：那个“改动”只是 ProjFS 把数据召回本地，
                // 立刻回收会让应用下一口气又去召回（读大文件会剧烈抖动）。
                // 记下来，交给空闲脱水（默认 60 s 没再读就收回明文）。
                if let Ok(mut hydrated) = inner.hydrated.lock() {
                    if hydrated.len() > 4000 {
                        hydrated.clear();
                    }
                    hydrated.insert(relative.clone(), std::time::Instant::now());
                }
            }
            if let Ok(mut sealed) = inner.sealed.lock() {
                sealed.insert(relative.clone(), plain_hash);
            }
            return Ok(());
        }

        let header = pek_outguard_core::container::Header {
            company: self.options.company.clone(),
            notice: self.options.notice.clone(),
            classification: self.options.classification.clone(),
            policy_id: self.options.policy_id.clone(),
            policy_version: 0,
            rule_id: String::new(),
            creator: dhrust::sys::machine::user_name(),
            client_id: String::new(),
            created_at: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            original_name: name,
            original_size: plain_size,
            plain_sha256: Some(pek_outguard_core::crypto::hex(&plain_hash)),
        };

        // ① 先写密文（同目录 .tmp 再改名）；输入直接来自文件句柄，全程流式。
        if let Some(parent) = vault_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("创建密文库目录失败：{e}"))?;
        }
        let temp = vault_path.with_extension(format!("{VAULT_EXT}.tmp"));
        {
            let mut input =
                std::fs::File::open(path).map_err(|e| format!("打开实体明文失败：{e}"))?;
            let mut out = std::fs::File::create(&temp)
                .map_err(|e| format!("创建密文失败（{}）：{e}", temp.display()))?;
            pek_outguard_core::container::encrypt_stream(&key, &header, &mut input, &mut out)
                .map_err(|e| format!("加密失败：{e}"))?;
        }
        // 用原子替换而不是裸 rename：杀软/备份/其他读取器恰好占着目标文件时，
        // 裸 rename 会 “拒绝访问” 直接失败（明文就得下次再试）；原子替换带重试。
        dhrust::io::safe_replace_file(&temp, &vault_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            format!("落位密文失败：{e}")
        })?;

        // 校验密文能完整解出来，否则不碰实体明文（这是不可逆丢失的唯一防线）。
        if let Err(e) = pek_outguard_core::container::verify_file(&vault_path, &key) {
            let _ = std::fs::remove_file(&vault_path);
            return Err(format!("密文校验失败（实体明文已保留）：{e}"));
        }

        // ② 让 ProjFS 把这个“实体明文文件”抷回占位符（按 flags 允许丢弃本地数据）。
        //    注意：不能先删再 PrjWritePlaceholderInfo——ProjFS 的目录缓存会把它当成已删除。
        demote_to_placeholder(self.context, &relative, path, plain_size as i64)?;
        if let Ok(mut hydrated) = inner.hydrated.lock() {
            hydrated.remove(&relative);
        }
        if let Ok(mut sealed) = inner.sealed.lock() {
            if sealed.len() > 4000 {
                sealed.clear();
            }
            sealed.insert(relative.clone(), plain_hash);
        }
        if let Some(sink) = &self.options.audit {
            (sink)("seal", &relative, Some(plain_size));
        }
        dhrust::info!(
            "已加密落盘：{relative}（{} 字节）；磁盘上只留密文",
            plain_size
        );
        Ok(())
    }
}

/// 读容器头里记录的明文 SHA-256（不存在/无记录返回 `None`）。
fn container_plain_hash(path: &Path) -> Option<String> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path).ok()?);
    let header = pek_outguard_core::container::read_header(&mut reader).ok()?;
    header.plain_sha256
}

/// 把"被写脏的实体文件"降级回占位符（丢弃本地明文数据）。
fn demote_to_placeholder(
    context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    relative: &str,
    full_path: &Path,
    size: i64,
) -> Result<(), String> {
    let info = placeholder_for(false, size, dehydrate_seed());
    let name_wide = wide(relative);
    let mut cause: i32 = 0;
    let hr = unsafe {
        PrjUpdateFileIfNeeded(
            context,
            name_wide.as_ptr(),
            &info,
            std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
            UPDATE_ALLOW_DIRTY_DATA | UPDATE_ALLOW_DIRTY_METADATA,
            &mut cause,
        )
    };
    if hr >= 0 {
        return Ok(());
    }
    // 兜底：删实体再重建占位符（部分系统版本对 Update 支持不全）。
    std::fs::remove_file(full_path).map_err(|e| format!("删除实体明文失败：{e}"))?;
    let hr2 = unsafe {
        PrjWritePlaceholderInfo(
            context,
            name_wide.as_ptr(),
            &info,
            std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
        )
    };
    if hr2 < 0 {
        return Err(format!(
            "恢复占位符失败（Update 0x{:08X}/cause {cause}，Write 0x{:08X}）",
            hr as u32, hr2 as u32
        ));
    }
    Ok(())
}

/// ProjFS 占位符带"数据按需召回"属性；实体文件没有。
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
/// ProjFS 在 provider 停止/水化后可能撤掉 recall 标志，改用"重解析点 + 稀疏"标记。
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;

/// 脱水时给 ContentID 换个新值：内容标识变了，ProjFS 才会把本地明文收回去。
/// （内容没变时若沿用同一个 ContentID，系统会认为“无需更新”，文件就一直留着明文。）
fn dehydrate_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
}

/// 是否是 ProjFS 占位符（而不是磁盘上的实体明文）。
///
/// 实测有两种形态：正常占位符带 `RECALL_ON_DATA_ACCESS`；
/// provider 停掉或水化后被 ProjFS 改回"重解析点 + 稀疏"（实测 9760）。
/// 两种都必须认，否则崩溃重启会把自家占位符当成"未加密文件"而拒绝启动。
fn is_placeholder(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    let attrs = meta.file_attributes();
    if attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0 {
        return true;
    }
    attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && attrs & FILE_ATTRIBUTE_SPARSE_FILE != 0
}

impl Drop for SecureArea {
    fn drop(&mut self) {
        // **停之前先把明文收回去**：ProjFS 一旦停掉，已水化的文件就变回普通实体文件，
        // 明文会一直躺在磁盘上（升级、重启、崩溃时最容易被忽略）。
        let inner = unsafe { &*self.inner };
        let hydrated = inner
            .hydrated
            .lock()
            .map(|map| map.len())
            .unwrap_or(0);
        if hydrated > 0 {
            // 先把已知水化的立刻收回，再全扫兜底（防止有水化但没记上的）。
            self.dehydrate_idle(std::time::Duration::ZERO);
        }
        let sealed = self.seal_dirty();
        if sealed > 0 {
            dhrust::warn!(
                "安全区停止前完成 {sealed} 个文件的收尾（有改动已加密回密文库）"
            );
        }
        unsafe {
            PrjStopVirtualizing(self.context);
            // 等回调线程退出后释放上下文。
            drop(Box::from_raw(self.inner as *mut Inner));
        }
        // 安全第一：停用时清掉遗留的明文缓存目录（旧版本才有）。
        let _ = std::fs::remove_dir_all(&self.options.cache);
        dhrust::info!("安全区已停止：{}", self.options.root.display());
    }
}

/// 内部上下文（回调通过 `InstanceContext` 拿到它）。
struct Inner {
    options: SecureAreaOptions,
    key: Arc<KeyResolver>,
    /// 枚举会话：枚举 GUID → 待派发的条目列表
    enumerations: Mutex<HashMap<String, Vec<Entry>>>,
    /// 已水化（ProjFS 已经把明文落在本地磁盘）的文件：相对路径 → 最后一次读取时间。
    /// 空闲后统一降级为占位符，避免明文长期留在磁盘上。
    hydrated: Mutex<HashMap<String, std::time::Instant>>,
    /// 刚看过的文件（大小 + mtime）：重复事件直接跳过，避免重复哈希大文件
    recent: Mutex<HashMap<String, (u64, i64, std::time::Instant)>>,
    /// 打开审计去重：相对路径 → 最近一次记录时间（同一文件 5 分钟内只记一条）
    opened: Mutex<HashMap<String, std::time::Instant>>,
    /// 上次落盘加密时的明文 SHA-256：内容没变就不重复加密（ProjFS 会反复触发 Modify）
    sealed: Mutex<HashMap<String, [u8; 32]>>,
}

/// 目录枚举项。
#[derive(Clone)]
struct Entry {
    /// 虚拟相对路径（如 `采购部\2026年度合同.txt`）
    relative: String,
    /// 是否是子目录
    is_dir: bool,
}

impl Inner {
    /// 虚拟相对路径（如 `采购合同.docx`）→ 密文库真实路径。
    fn vault_path(&self, relative: &str) -> PathBuf {
        self.options
            .vault
            .join(format!("{relative}.{VAULT_EXT}"))
    }

    /// 只读容器头取明文大小（枚举用；**不解密全文**，大目录不会卡）。
    fn file_size(&self, relative: &str) -> Option<i64> {
        let mut reader = std::io::BufReader::new(
            std::fs::File::open(self.vault_path(relative)).ok()?,
        );
        let header = pek_outguard_core::container::read_header(&mut reader).ok()?;
        Some(header.original_size as i64)
    }

    /// 按需解密 `[offset, offset+length)` 这一段明文。
    ///
    /// **不落明文缓存、不把整文件读进内存**：应用读 4 KB 就只解一个分块，
    /// 几百 MB 的图纸也只占几 MB 内存。
    fn plain_range(&self, relative: &str, offset: u64, length: u64) -> Option<Vec<u8>> {
        let path = self.vault_path(relative);
        let mut reader = std::io::BufReader::new(std::fs::File::open(&path).ok()?);
        let header = pek_outguard_core::container::read_header(&mut reader)
            .inspect_err(|e| dhrust::warn!("安全区读容器头失败（{relative}）：{e}"))
            .ok()?;
        let key = (self.key)(&header.policy_id)?;
        let mut out = Vec::with_capacity(length.min(4 * 1024 * 1024) as usize);
        let size = pek_outguard_core::container::decrypt_range(
            &path,
            &key,
            offset,
            length,
            &mut out,
        )
        .inspect_err(|e| dhrust::warn!("安全区解密失败（{relative} @{offset}）：{e}"))
        .ok()?;
        if size > 0
            && let Ok(mut hydrated) = self.hydrated.lock()
        {
            if hydrated.len() > 4000 {
                hydrated.clear();
            }
            hydrated.insert(relative.to_string(), std::time::Instant::now());
        }
        self.audit_open(relative, header.original_size);
        Some(out)
    }

    fn audit_open(&self, relative: &str, size: u64) {
        let Some(sink) = &self.options.audit else {
            return;
        };
        let Ok(mut opened) = self.opened.lock() else {
            return;
        };
        let now = std::time::Instant::now();
        if let Some(last) = opened.get(relative)
            && now.duration_since(*last).as_secs() < 300
        {
            return;
        }
        // 表有界：超过 2000 条直接清空（只需近期去重，不持久）。
        if opened.len() > 2000 {
            opened.clear();
        }
        opened.insert(relative.to_string(), now);
        drop(opened);
        (sink)("open", relative, Some(size));
    }

    /// 密文库内某个相对目录的真实路径（用于判断是不是目录）。
    fn vault_dir(&self, relative: &str) -> PathBuf {
        if relative.is_empty() {
            self.options.vault.clone()
        } else {
            self.options.vault.join(relative)
        }
    }

    /// 枚举密文库某目录下的文件与子目录（返回虚拟相对路径）。
    fn list(&self, relative_dir: &str) -> Vec<Entry> {
        let dir = self.vault_dir(relative_dir);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // 跳过内部文件（`.instance-id` 等）。
            if name.starts_with('.') {
                continue;
            }
            let join = |child: &str| {
                if relative_dir.is_empty() {
                    child.to_string()
                } else {
                    format!("{relative_dir}\\{child}")
                }
            };
            if entry.path().is_dir() {
                out.push(Entry {
                    relative: join(&name),
                    is_dir: true,
                });
            } else if let Some(stem) = name.strip_suffix(&format!(".{VAULT_EXT}")) {
                out.push(Entry {
                    relative: join(stem),
                    is_dir: false,
                });
            }
        }
        out
    }
}

/// 启动安全区虚拟化。
pub fn start(options: SecureAreaOptions, key: Arc<KeyResolver>) -> Result<SecureArea, String> {
    if !options.root.is_dir() {
        return Err(format!(
            "安全区目录不存在：{}（需先创建空目录）",
            options.root.display()
        ));
    }
    // 与 CLI/服务共用同一套检查：允许残留本程序自己的占位符（崩溃/升级后要能接管），
    // 只拒绝真正的明文实体文件。
    check_area(&options.root)?;
    std::fs::create_dir_all(&options.vault).map_err(|e| format!("创建密文库失败：{e}"))?;
    // 旧版会把解密结果写在 `options.cache` 目录里——新版改成按需区间解密，
    // 这里只做一次性清理（不留历史明文残留），不再创建这个目录。
    if options.cache.is_dir() {
        let _ = std::fs::remove_dir_all(&options.cache);
    }

    let inner = Box::into_raw(Box::new(Inner {
        options: options.clone(),
        key,
        enumerations: Mutex::new(HashMap::new()),
        hydrated: Mutex::new(HashMap::new()),
        recent: Mutex::new(HashMap::new()),
        opened: Mutex::new(HashMap::new()),
        sealed: Mutex::new(HashMap::new()),
    }));

    let callbacks = PRJ_CALLBACKS {
        StartDirectoryEnumerationCallback: Some(cb_start_enum),
        EndDirectoryEnumerationCallback: Some(cb_end_enum),
        GetDirectoryEnumerationCallback: Some(cb_get_enum),
        GetPlaceholderInfoCallback: Some(cb_placeholder),
        GetFileDataCallback: Some(cb_file_data),
        QueryFileNameCallback: None,
        NotificationCallback: None,
        CancelCommandCallback: None,
    };

    let root_wide = wide(options.root.as_os_str().to_string_lossy().as_ref());
    let mut context: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT = std::ptr::null_mut();

    // 文档要求：必须先把这个目录标记为虚拟化根（只需一次），否则 StartVirtualizing 会报 4390。
    let instance_id = load_or_create_instance_id(&options.vault);
    let mark = unsafe {
        PrjMarkDirectoryAsPlaceholder(
            root_wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            &instance_id,
        )
    };
    if mark < 0 {
        // 已经标记过会返回其它错误码；不当作致命，继续尝试启动。
        dhrust::warn!(
            "标记虚拟化根返回 0x{:08X}（已标记过可忽略）：{}",
            mark as u32,
            options.root.display()
        );
    }

    // options 传 NULL = 全部默认（避免结构体版本差异导致参数错位）。
    let hr = unsafe {
        PrjStartVirtualizing(
            root_wide.as_ptr(),
            &callbacks,
            inner as *const c_void,
            std::ptr::null(),
            &mut context,
        )
    };
    if hr < 0 {
        unsafe { drop(Box::from_raw(inner)) };
        return Err(format!(
            "启动安全区失败（HRESULT 0x{:08X}）：{}；请确认目录为空且非已虚拟化",
            hr as u32,
            options.root.display()
        ));
    }

    let mut info = PRJ_VIRTUALIZATION_INSTANCE_INFO {
        InstanceID: zero_guid(),
        WriteAlignment: 0,
    };
    let aligned = unsafe { PrjGetVirtualizationInstanceInfo(context, &mut info) } >= 0;
    dhrust::info!(
        "安全区已启用：{} → 密文库 {}（写对齐 {} 字节{}）",
        options.root.display(),
        options.vault.display(),
        info.WriteAlignment,
        if aligned { "" } else { "，取对齐失败" }
    );

    Ok(SecureArea {
        context,
        inner,
        options,
    })
}

// ————— 回调 —————

unsafe extern "system" fn cb_start_enum(
    data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const windows_sys::core::GUID,
) -> i32 {
    let inner = unsafe { inner_of(data) };
    let Some(path) = (unsafe { rel_path(data) }) else {
        return HR_FILE_NOT_FOUND;
    };
    let key = guid_key(unsafe { &*enumeration_id });
    if let Ok(mut map) = inner.enumerations.lock() {
        if data.is_null() {
            return E_FAIL;
        }
        let restart = (unsafe { (*data).Flags } & ENUM_RESTART_SCAN) != 0;
        if restart {
            map.remove(&key);
        }
        map.entry(key).or_insert_with(|| inner.list(&normalize_dir(&path)));
        return S_OK;
    }
    E_FAIL
}

unsafe extern "system" fn cb_end_enum(
    data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const windows_sys::core::GUID,
) -> i32 {
    let inner = unsafe { inner_of(data) };
    let key = guid_key(unsafe { &*enumeration_id });
    if let Ok(mut map) = inner.enumerations.lock() {
        map.remove(&key);
    }
    S_OK
}

unsafe extern "system" fn cb_get_enum(
    data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const windows_sys::core::GUID,
    search_expression: *const u16,
    buffer: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> i32 {
    let inner = unsafe { inner_of(data) };
    let key = guid_key(unsafe { &*enumeration_id });
    let Ok(mut map) = inner.enumerations.lock() else {
        return E_FAIL;
    };
    let Some(entries) = map.get_mut(&key) else {
        return E_FAIL;
    };

    let search = if search_expression.is_null() {
        String::new()
    } else {
        unsafe { wide_to_string(search_expression) }
    };

    while let Some(entry) = entries.first().cloned() {
        entries.remove(0);
        let name = Path::new(&entry.relative)
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| entry.relative.clone());
        // 通配匹配（`*` 即可；不实现完整的 DOS 通配以免复杂化）。
        if !search.is_empty() && search != "*" && !dhrust::io::wildcard_match(&name, &search) {
            continue;
        }
        let info = if entry.is_dir {
            dir_basic_info()
        } else {
            let size = inner.file_size(&entry.relative).unwrap_or(0);
            basic_info(size, None)
        };
        let name_wide = wide(&name);
        let hr = unsafe { PrjFillDirEntryBuffer(name_wide.as_ptr(), &info, buffer) };
        if hr < 0 {
            // 缓冲满：把当前条目放回队首，等下一轮。
            entries.insert(0, entry);
            return S_OK;
        }
    }
    S_OK
}

unsafe extern "system" fn cb_placeholder(data: *const PRJ_CALLBACK_DATA) -> i32 {
    let inner = unsafe { inner_of(data) };
    let Some(path) = (unsafe { rel_path(data) }) else {
        return HR_FILE_NOT_FOUND;
    };
    if path.is_empty() {
        // 根目录本身不需要占位信息。
        return S_OK;
    }

    // 子目录：密文库里有同名目录就当成目录占位符。
    if inner.vault_dir(&path).is_dir() {
        let placeholder = placeholder_for(true, 0, 0);
        let name_wide = wide(&path);
        let hr = unsafe {
            PrjWritePlaceholderInfo(
                (*data).NamespaceVirtualizationContext,
                name_wide.as_ptr(),
                &placeholder,
                std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
            )
        };
        return if hr < 0 { hr } else { S_OK };
    }

    let Some(size) = inner.file_size(&path) else {
        return HR_FILE_NOT_FOUND;
    };
    let placeholder = placeholder_for(false, size, 0);
    let name_wide = wide(&path);
    let hr = unsafe {
        PrjWritePlaceholderInfo(
            (*data).NamespaceVirtualizationContext,
            name_wide.as_ptr(),
            &placeholder,
            std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
        )
    };
    if hr < 0 { hr } else { S_OK }
}

unsafe extern "system" fn cb_file_data(
    data: *const PRJ_CALLBACK_DATA,
    byte_offset: u64,
    length: u32,
) -> i32 {
    let inner = unsafe { inner_of(data) };
    let Some(path) = (unsafe { rel_path(data) }) else {
        return HR_FILE_NOT_FOUND;
    };
    if length == 0 {
        return S_OK;
    }
    // 按需区间解密：只解这段字节，**不落明文缓存、不把整文件读进内存**。
    let Some(plain) = inner.plain_range(&path, byte_offset, length as u64) else {
        return HR_FILE_NOT_FOUND;
    };
    if plain.is_empty() {
        return S_OK;
    }
    let hr = unsafe {
        PrjWriteFileData(
            (*data).NamespaceVirtualizationContext,
            &(*data).DataStreamId,
            plain.as_ptr() as *const c_void,
            byte_offset,
            plain.len() as u32,
        )
    };
    if hr < 0 { hr } else { S_OK }
}

// ————— 回调内的安全小工具 —————

unsafe fn inner_of(data: *const PRJ_CALLBACK_DATA) -> &'static Inner {
    unsafe { &*((*data).InstanceContext as *const Inner) }
}

/// 回调里的文件路径 → 虚拟相对路径（去掉前导 `\`，统一反斜杠）。
unsafe fn rel_path(data: *const PRJ_CALLBACK_DATA) -> Option<String> {
    if data.is_null() {
        return None;
    }
    let raw = unsafe { (*data).FilePathName };
    if raw.is_null() {
        return None;
    }
    let text = unsafe { wide_to_string(raw) };
    let trimmed = text.trim_start_matches(['\\', '/']).replace('/', "\\");
    Some(trimmed)
}

fn normalize_dir(relative: &str) -> String {
    relative.trim_matches(['\\', '/']).replace('/', "\\")
}

fn zero_guid() -> windows_sys::core::GUID {
    windows_sys::core::GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0u8; 8],
    }
}

/// 实例 ID：同一安全区必须复用同一个 GUID，否则系统会当成另一个虚拟化实例。
///
/// 存在密文库旁边的 `.instance-id`（16 字节）；丢失会重新生成（旧的 placeholder 可能需重建）。
fn load_or_create_instance_id(vault: &Path) -> windows_sys::core::GUID {
    let path = vault.join(".instance-id");
    if let Ok(bytes) = std::fs::read(&path)
        && bytes.len() == 16
    {
        return windows_sys::core::GUID {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]],
        };
    }
    let bytes = dhrust::random::bytes(16);
    let _ = std::fs::create_dir_all(vault);
    let _ = std::fs::write(&path, &bytes);
    windows_sys::core::GUID {
        data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_le_bytes([bytes[4], bytes[5]]),
        data3: u16::from_le_bytes([bytes[6], bytes[7]]),
        data4: [bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]],
    }
}

/// 枚举会话键（GUID 没有 Debug/Display，转成稳定字符串）。
fn guid_key(guid: &windows_sys::core::GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

fn basic_info(size: i64, timestamp: Option<i64>) -> PRJ_FILE_BASIC_INFO {
    let time = timestamp.unwrap_or(0);
    PRJ_FILE_BASIC_INFO {
        IsDirectory: 0,
        FileSize: size,
        CreationTime: time,
        LastAccessTime: time,
        LastWriteTime: time,
        ChangeTime: time,
        // FILE_ATTRIBUTE_NORMAL
        FileAttributes: 0x80,
    }
}

fn dir_basic_info() -> PRJ_FILE_BASIC_INFO {
    PRJ_FILE_BASIC_INFO {
        IsDirectory: 1,
        FileSize: 0,
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        // FILE_ATTRIBUTE_DIRECTORY
        FileAttributes: 0x10,
    }
}

fn placeholder_for(is_dir: bool, size: i64, seed: u64) -> PRJ_PLACEHOLDER_INFO {
    let mut content_id = [0u8; 128];
    content_id[..8].copy_from_slice(&seed.to_le_bytes());
    PRJ_PLACEHOLDER_INFO {
        FileBasicInfo: if is_dir {
            dir_basic_info()
        } else {
            basic_info(size, None)
        },
        EaInformation: windows_sys::Win32::Storage::ProjectedFileSystem::PRJ_PLACEHOLDER_INFO_0 {
            EaBufferSize: 0,
            OffsetToFirstEa: 0,
        },
        SecurityInformation:
            windows_sys::Win32::Storage::ProjectedFileSystem::PRJ_PLACEHOLDER_INFO_1 {
                SecurityBufferSize: 0,
                OffsetToSecurityDescriptor: 0,
            },
        StreamsInformation:
            windows_sys::Win32::Storage::ProjectedFileSystem::PRJ_PLACEHOLDER_INFO_2 {
                StreamsInfoBufferSize: 0,
                OffsetToFirstStreamInfo: 0,
            },
        VersionInfo: PRJ_PLACEHOLDER_VERSION_INFO {
            ProviderID: [0u8; 128],
            ContentID: content_id,
        },
        VariableData: [0u8; 1],
    }
}

/// 启动前"吸收"目录里残留的**明文实体文件**（上次异常退出、或用户手工拷进去的）：
/// 加密进密文库并删除，保证目录为空才能启动 ProjFS。返回吸收的文件数。
pub fn absorb_existing(options: &SecureAreaOptions, key: &[u8; 32]) -> Result<usize, String> {
    if !options.root.is_dir() {
        return Ok(0);
    }
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut stack = vec![options.root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(path.clone());
                dirs.push(path);
            } else if is_placeholder(&meta) {
                // 本程序自己的占位符：这里 ProjFS 还没启动，读它没有意义，
                // 交给启动后的 seal 兜底（脏数据由 ProjFS 自己保留）。
                continue;
            } else {
                files.push(path);
            }
        }
    }

    let mut absorbed = 0usize;
    for path in files {
        let relative = path
            .strip_prefix(&options.root)
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();
        if relative.is_empty() {
            continue;
        }
        match import_file(options, key, &path, &relative, false) {
            Ok(_) => absorbed += 1,
            Err(e) => dhrust::warn!("吸收残留明文失败（{}）：{e}", path.display()),
        }
    }
    // 清掉空子目录（ProjFS 要求根目录为空）
    for dir in dirs.into_iter().rev() {
        let _ = std::fs::remove_dir(&dir);
    }
    if absorbed > 0 {
        dhrust::info!("安全区启动前吸收了 {absorbed} 个残留明文文件（已加密进密文库）");
    }
    Ok(absorbed)
}

/// 导入一个明文文件到密文库（安全区里**立刻**就能看到它，磁盘上只存密文）。
///
/// 这是"把已有文档搬进安全区"的入口：原文件按 `keep_source` 决定保留还是删除。
pub fn import_file(
    options: &SecureAreaOptions,
    key: &[u8; 32],
    source: &Path,
    relative: &str,
    keep_source: bool,
) -> Result<PathBuf, String> {
    if !source.is_file() {
        return Err(format!("源文件不存在：{}", source.display()));
    }
    if relative.trim().is_empty() {
        return Err("目标相对路径不能为空".into());
    }
    // 流式：几百 MB 的图纸也不会把进程撑爆。
    let plain_size = std::fs::metadata(source)
        .map_err(|e| format!("读取源文件信息失败：{e}"))?
        .len();
    let plain_hash = pek_outguard_core::crypto::sha256_file(source)
        .map_err(|e| format!("计算源文件哈希失败：{e}"))?;
    let name = Path::new(relative)
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| relative.to_string());

    let header = pek_outguard_core::container::Header {
        company: options.company.clone(),
        notice: options.notice.clone(),
        classification: options.classification.clone(),
        policy_id: options.policy_id.clone(),
        policy_version: 0,
        rule_id: String::new(),
        creator: dhrust::sys::machine::user_name(),
        client_id: String::new(),
        created_at: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        original_name: name,
        original_size: plain_size,
        plain_sha256: Some(pek_outguard_core::crypto::hex(&plain_hash)),
    };

    let vault_path = options
        .vault
        .join(format!("{}.{VAULT_EXT}", relative.replace('/', "\\")));
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建密文库目录失败：{e}"))?;
    }
    let temp = vault_path.with_extension(format!("{VAULT_EXT}.tmp"));
    {
        let mut input =
            std::fs::File::open(source).map_err(|e| format!("打开源文件失败：{e}"))?;
        let mut out = std::fs::File::create(&temp)
            .map_err(|e| format!("创建密文失败（{}）：{e}", temp.display()))?;
        pek_outguard_core::container::encrypt_stream(key, &header, &mut input, &mut out)
            .map_err(|e| format!("加密失败：{e}"))?;
    }
    dhrust::io::safe_replace_file(&temp, &vault_path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("落位密文失败：{e}")
    })?;

    // 校验密文能完整解出来，通过后才允许删源文件。
    if let Err(e) = pek_outguard_core::container::verify_file(&vault_path, key) {
        let _ = std::fs::remove_file(&vault_path);
        return Err(format!("密文校验失败（源文件未删）：{e}"));
    }

    if !keep_source
        && let Err(e) = std::fs::remove_file(source)
    {
        dhrust::warn!(
            "导入成功但删除源文件失败（{}）：{e}（请手动清理）",
            source.display()
        );
    }
    if let Some(sink) = &options.audit {
        (sink)("import", relative, Some(plain_size));
    }
    Ok(vault_path)
}

/// 批量导入要跳过的“垃圾文件”。
///
/// 办公目录里常见：Office 锁文件 `~$xxx.docx`、系统缩略图 `Thumbs.db`/`desktop.ini`、
/// 编辑器临时文件 `*.tmp`/`*.bak`、隐藏文件（以 `.` 开头）。这些搬进密文库没有意义，
/// 还会让用户看到一堆莫名其妙的条目。
pub fn should_skip_import(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    name.is_empty()
        || name.starts_with('.')
        || lower.starts_with("~$")
        || lower.ends_with(".tmp")
        || lower.ends_with(".bak")
        || lower.ends_with(".crdownload")
        || lower.ends_with(".part")
        || matches!(lower.as_str(), "thumbs.db" | "desktop.ini" | "$recycle.bin")
}

/// 批量导入结果。
#[derive(Debug, Default)]
pub struct ImportReport {
    /// 成功导入的文件数
    pub imported: usize,
    /// 因目标已存在而跳过的文件数（不覆盖，避免毁掉用户旧版本）
    pub skipped: usize,
    /// 因错误失败的文件数
    pub failed: usize,
    /// 成功导入的总字节数
    pub bytes: u64,
    /// 失败明细（最多保留 20 条，避免刷屏；完整原因已写日志）
    pub failures: Vec<(String, String)>,
}

impl ImportReport {
    /// 一句话摘要（给 CLI 直接打印）。
    pub fn summary(&self) -> String {
        format!(
            "导入 {} 个（{:.1} MB），跳过 {} 个已存在，失败 {} 个",
            self.imported,
            self.bytes as f64 / 1024.0 / 1024.0,
            self.skipped,
            self.failed
        )
    }
}

/// 批量导入一个目录（保留相对目录结构）。
///
/// - `target_prefix` 为空 = 直接放在安全区根下；否则当作目标子目录（如 `技术部\2026`）。
/// - **不覆盖**已存在的同名密文（算作跳过并提示），避免把用户旧版本冲掉。
/// - 单个文件失败不中断整批（记录后继续），最后给出汇总。
pub fn import_tree(
    options: &SecureAreaOptions,
    key: &[u8; 32],
    source_dir: &Path,
    target_prefix: &str,
    keep_source: bool,
) -> Result<ImportReport, String> {
    if !source_dir.is_dir() {
        return Err(format!("源目录不存在：{}", source_dir.display()));
    }
    let mut report = ImportReport::default();
    use std::os::windows::fs::MetadataExt as _;
    let prefix = target_prefix.trim().trim_matches('\\').to_string();
    let mut stack = vec![source_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            dhrust::warn!("跳过无法读取的目录：{}", dir.display());
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            // 重解析点（符号链接/联接点）一律不跟随，避免环路与越界。
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                dhrust::warn!("跳过符号链接/联接点：{}", path.display());
                continue;
            }
            let name = path
                .file_name()
                .map(|v| v.to_string_lossy().to_string())
                .unwrap_or_default();
            if should_skip_import(&name) {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(sub) = path.strip_prefix(source_dir) else {
                continue;
            };
            let sub = sub.to_string_lossy().to_string();
            let relative = if prefix.is_empty() {
                sub
            } else {
                format!("{prefix}\\{sub}")
            };
            let vault_path = options
                .vault
                .join(format!("{}.{VAULT_EXT}", relative.replace('/', "\\")));
            if vault_path.is_file() {
                report.skipped += 1;
                dhrust::info!("已存在，跳过：{relative}");
                continue;
            }
            match import_file(options, key, &path, &relative, keep_source) {
                Ok(_) => {
                    report.imported += 1;
                    report.bytes += meta.len();
                }
                Err(e) => {
                    report.failed += 1;
                    dhrust::warn!("导入失败（{relative}）：{e}");
                    if report.failures.len() < 20 {
                        report.failures.push((relative, e));
                    }
                }
            }
        }
    }
    dhrust::info!("批量导入完成：{}", report.summary());
    Ok(report)
}

/// 安全区是否可用（系统支持 ProjFS 且目录里没有“别人的实体文件”）。
///
/// 注意：**允许残留本程序自己的占位符**。服务被强杀/升级后，目录里会留下
/// 带“按需召回”属性的占位符文件——那是 ProjFS 的正常产物，重启后要能直接接管；
/// 若把它们当成“已有文件”而拒绝启动，一次崩溃就会让安全区永久起不来。
pub fn check_area(root: &Path) -> Result<(), String> {
    if !crate::projfs::is_supported() {
        return Err("系统不支持 ProjFS（需 Windows 10 1809+ / Server 2019+）".into());
    }
    if !root.is_dir() {
        return Err(format!("安全区目录不存在：{}", root.display()));
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if is_placeholder(&meta) {
                continue; // 本程序自己的占位符，留着
            }
            return Err(format!(
                "安全区目录里存在未加密的文件，请先移走：{}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_and_back_conversion() {
        let buffer = wide("采购合同.docx");
        let text = unsafe { wide_to_string(buffer.as_ptr()) };
        assert_eq!(text, "采购合同.docx");
    }

    #[test]
    fn normalize_dir_strips_leading_separators() {
        assert_eq!(normalize_dir("\\sub\\dir"), "sub\\dir");
        assert_eq!(normalize_dir("/sub/dir"), "sub\\dir");
        assert_eq!(normalize_dir(""), "");
    }

    #[test]
    fn import_skips_office_lock_and_system_junk() {
        // Office 锁文件、缩略图、临时文件、隐藏文件一律不搬进密文库
        assert!(should_skip_import("~$采购合同.docx"));
        assert!(should_skip_import("Thumbs.db"));
        assert!(should_skip_import("desktop.ini"));
        assert!(should_skip_import("a.tmp"));
        assert!(should_skip_import("a.BAK"));
        assert!(should_skip_import("x.crdownload"));
        assert!(should_skip_import(".gitignore"));
        assert!(should_skip_import(""));
        // 正常文档照常导入
        assert!(!should_skip_import("采购合同.docx"));
        assert!(!should_skip_import("设计图纸.dwg"));
        assert!(!should_skip_import("报表.xlsx"));
    }

    #[test]
    fn vault_path_appends_container_extension() {
        let inner = Inner {
            options: SecureAreaOptions {
                root: PathBuf::from("D:/Secure"),
                vault: PathBuf::from("D:/Vault"),
                cache: PathBuf::from("D:/Cache"),
                policy_id: "default".into(),
                company: "示例".into(),
                notice: "内部".into(),
                classification: "内部".into(),
                audit: None,
            },
            key: Arc::new(|_| Some([0u8; 32])),
            enumerations: Mutex::new(HashMap::new()),
            hydrated: Mutex::new(HashMap::new()),
            recent: Mutex::new(HashMap::new()),
            opened: Mutex::new(HashMap::new()),
            sealed: Mutex::new(HashMap::new()),
        };
        let path = inner.vault_path("sub\\采购合同.docx");
        assert!(path.to_string_lossy().ends_with("采购合同.docx.ogd"));
    }

    #[test]
    fn check_area_rejects_missing_or_non_empty() {
        let missing = PathBuf::from(r"Z:\definitely-missing-outguard");
        assert!(check_area(&missing).is_err());
    }
}
