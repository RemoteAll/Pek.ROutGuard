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
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
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
    /// 把安全区里的**实体明文文件**加密搬进密文库，并恢复成占位符。
    ///
    /// ProjFS 的写入是"落成本地实体文件"，所以每次用户保存后都要走这一步，
    /// 否则磁盘上会留下明文。返回处理的文件数。
    pub fn seal_dirty(&self) -> usize {
        let inner = unsafe { &*self.inner };
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
                match self.seal_one(inner, &path) {
                    Ok(()) => sealed += 1,
                    Err(e) => dhrust::warn!("安全区落盘加密失败（{}）：{e}", path.display()),
                }
            }
        }
        if sealed > 0 {
            dhrust::info!("安全区已加密 {sealed} 个改动文件（磁盘上只留密文）");
        }
        sealed
    }

    fn seal_one(&self, inner: &Inner, path: &Path) -> Result<(), String> {
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
        let plain = std::fs::read(path).map_err(|e| format!("读取实体文件失败：{e}"))?;
        let plain_hash = pek_outguard_core::crypto::sha256(&plain);
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
            demote_to_placeholder(self.context, &relative, path, plain.len() as i64)?;
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
            original_size: plain.len() as u64,
            plain_sha256: Some(pek_outguard_core::crypto::hex(
                &pek_outguard_core::crypto::sha256(&plain),
            )),
        };

        // ① 先写密文（同目录 .tmp 再改名）
        if let Some(parent) = vault_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("创建密文库目录失败：{e}"))?;
        }
        let temp = vault_path.with_extension(format!("{VAULT_EXT}.tmp"));
        {
            let mut input = std::io::Cursor::new(&plain);
            let mut out = std::fs::File::create(&temp)
                .map_err(|e| format!("创建密文失败（{}）：{e}", temp.display()))?;
            pek_outguard_core::container::encrypt_stream(&key, &header, &mut input, &mut out)
                .map_err(|e| format!("加密失败：{e}"))?;
        }
        std::fs::rename(&temp, &vault_path).map_err(|e| {
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
        demote_to_placeholder(self.context, &relative, path, plain.len() as i64)?;
        // 容器变了 → 缓存失效
        if let Ok(mut cache) = inner.cache.lock() {
            cache.remove(&relative);
        }
        if let Ok(mut sealed) = inner.sealed.lock() {
            if sealed.len() > 4000 {
                sealed.clear();
            }
            sealed.insert(relative.clone(), plain_hash);
        }
        if let Some(sink) = &self.options.audit {
            (sink)("seal", &relative, Some(plain.len() as u64));
        }
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
    let info = placeholder_for(false, size);
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

fn is_placeholder(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0
}

impl Drop for SecureArea {
    fn drop(&mut self) {
        unsafe {
            PrjStopVirtualizing(self.context);
            // 等回调线程退出后释放上下文。
            drop(Box::from_raw(self.inner as *mut Inner));
        }
        dhrust::info!("安全区已停止：{}", self.options.root.display());
    }
}

/// 内部上下文（回调通过 `InstanceContext` 拿到它）。
struct Inner {
    options: SecureAreaOptions,
    key: Arc<KeyResolver>,
    /// 枚举会话：枚举 GUID → 待派发的条目列表
    enumerations: Mutex<HashMap<String, Vec<Entry>>>,
    /// 解密缓存：相对路径 → 明文内容（容器 mtime 变化就重建）
    cache: Mutex<HashMap<String, Arc<CachedPlain>>>,
    /// 打开审计去重：相对路径 → 最近一次记录时间（同一文件 5 分钟内只记一条）
    opened: Mutex<HashMap<String, std::time::Instant>>,
    /// 上次落盘加密时的明文 SHA-256：内容没变就不重复加密（ProjFS 会反复触发 Modify）
    sealed: Mutex<HashMap<String, [u8; 32]>>,
}

struct CachedPlain {
    /// 容器修改时间（失效判定）
    stamp: (u64, i64),
    data: Vec<u8>,
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

    /// 取明文（带缓存）。
    fn plain(&self, relative: &str) -> Option<Arc<CachedPlain>> {
        let path = self.vault_path(relative);
        let meta = std::fs::metadata(&path).ok()?;
        let stamp = (
            meta.len(),
            meta.modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );
        if let Ok(cache) = self.cache.lock()
            && let Some(hit) = cache.get(relative)
            && hit.stamp == stamp
        {
            return Some(Arc::clone(hit));
        }

        // 缓存未命中：整文件解密（第一版；大文件后续按需分块）。
        let key = {
            let mut reader = std::io::BufReader::new(std::fs::File::open(&path).ok()?);
            let header = pek_outguard_core::container::read_header(&mut reader).ok()?;
            (self.key)(&header.policy_id)?
        };
        let mut reader = std::io::BufReader::new(std::fs::File::open(&path).ok()?);
        let mut data = Vec::new();
        let mut out = std::io::Cursor::new(&mut data);
        pek_outguard_core::container::decrypt_stream(&key, &mut reader, &mut out).ok()?;

        let entry = Arc::new(CachedPlain { stamp, data });
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(relative.to_string(), Arc::clone(&entry));
        }
        // 审计：同一文件 5 分钟内只记一条（避免流式读触发几十条重复事件）。
        self.audit_open(relative, entry.data.len() as u64);
        Some(entry)
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
    let has_files = std::fs::read_dir(&options.root)
        .map_err(|e| format!("读取安全区目录失败：{e}"))?
        .flatten()
        .next()
        .is_some();
    if has_files {
        return Err(format!(
            "安全区目录必须为空（ProjFS 要求）：{}",
            options.root.display()
        ));
    }
    std::fs::create_dir_all(&options.vault).map_err(|e| format!("创建密文库失败：{e}"))?;
    std::fs::create_dir_all(&options.cache).map_err(|e| format!("创建缓存目录失败：{e}"))?;

    let inner = Box::into_raw(Box::new(Inner {
        options: options.clone(),
        key,
        enumerations: Mutex::new(HashMap::new()),
        cache: Mutex::new(HashMap::new()),
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
        let placeholder = placeholder_for(true, 0);
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
    let placeholder = placeholder_for(false, size);
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
    let Some(plain) = inner.plain(&path) else {
        return HR_FILE_NOT_FOUND;
    };
    let start = byte_offset as usize;
    if start > plain.data.len() {
        return E_INVALIDARG;
    }
    let end = (start + length as usize).min(plain.data.len());
    let slice = &plain.data[start..end];
    if slice.is_empty() {
        return S_OK;
    }
    let hr = unsafe {
        PrjWriteFileData(
            (*data).NamespaceVirtualizationContext,
            &(*data).DataStreamId,
            slice.as_ptr() as *const c_void,
            byte_offset,
            slice.len() as u32,
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

fn placeholder_for(is_dir: bool, size: i64) -> PRJ_PLACEHOLDER_INFO {
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
            ContentID: [0u8; 128],
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
    let plain = std::fs::read(source).map_err(|e| format!("读取源文件失败：{e}"))?;
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
        original_size: plain.len() as u64,
        plain_sha256: Some(pek_outguard_core::crypto::hex(
            &pek_outguard_core::crypto::sha256(&plain),
        )),
    };

    let vault_path = options
        .vault
        .join(format!("{}.{VAULT_EXT}", relative.replace('/', "\\")));
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建密文库目录失败：{e}"))?;
    }
    let temp = vault_path.with_extension(format!("{VAULT_EXT}.tmp"));
    {
        let mut input = std::io::Cursor::new(&plain);
        let mut out = std::fs::File::create(&temp)
            .map_err(|e| format!("创建密文失败（{}）：{e}", temp.display()))?;
        pek_outguard_core::container::encrypt_stream(key, &header, &mut input, &mut out)
            .map_err(|e| format!("加密失败：{e}"))?;
    }
    std::fs::rename(&temp, &vault_path).map_err(|e| {
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
        (sink)("import", relative, Some(plain.len() as u64));
    }
    Ok(vault_path)
}

/// 安全区是否可用（系统支持 ProjFS 且目录为空）。
pub fn check_area(root: &Path) -> Result<(), String> {
    if !crate::projfs::is_supported() {
        return Err("系统不支持 ProjFS（需 Windows 10 1809+ / Server 2019+）".into());
    }
    if !root.is_dir() {
        return Err(format!("安全区目录不存在：{}", root.display()));
    }
    if std::fs::read_dir(root)
        .map_err(|e| format!("读取安全区失败：{e}"))?
        .flatten()
        .next()
        .is_some()
    {
        return Err(format!(
            "安全区目录必须为空（已有文件请先移走）：{}",
            root.display()
        ));
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
            cache: Mutex::new(HashMap::new()),
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
