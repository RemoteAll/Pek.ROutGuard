//! 本地操作：规则判定 / 容器加密 / 容器解密 / 受控打开。

use std::path::{Path, PathBuf};

use base64::Engine as _;
use pek_outguard_core::container::{self, Header};
use pek_outguard_core::crypto;
use pek_outguard_core::rules::{Action, Decision, FileContext, PolicySet};

use crate::state::ClientState;

/// 判定结果。
pub struct Judgement {
    /// 命中的规则集（加密时用它派生密钥）
    pub policy: PolicySet,
    /// 判定
    pub decision: Decision,
}

/// 加密结果。
#[derive(Debug)]
pub struct EncryptOutcome {
    /// 输出容器路径（演练模式下是"计划路径"，文件并未产生）
    pub output: PathBuf,
    /// 生效规则集
    pub policy_id: String,
    /// 命中规则
    pub rule_id: String,
    /// 明文大小
    pub plain_size: u64,
    /// 是否真正写了文件（演练模式为 `false`，此时**磁盘上什么都没变**）
    pub applied: bool,
}

/// 加密选项（默认最安全：演练、不动原文件）。
#[derive(Debug, Clone)]
pub struct EncryptOptions {
    /// 演练模式：只判定与返回计划，不创建、不替换、不删除任何文件
    pub dry_run: bool,
    /// 原文件回收目录（`Some` = 加密后把原文件移到此处而不是删除）
    pub recovery_dir: Option<PathBuf>,
    /// 写完容器后回读校验（确认能完整解密再动原文件）
    pub verify: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            dry_run: true,
            recovery_dir: None,
            verify: true,
        }
    }
}

impl EncryptOptions {
    /// 实盘模式（会真正加密并移走原文件）。
    pub fn live(recovery_dir: PathBuf) -> Self {
        Self {
            dry_run: false,
            recovery_dir: Some(recovery_dir),
            verify: true,
        }
    }
}

/// 按服务端策略判定（多规则集：任一要求加密即加密；否则返回第一个判定）。
pub fn judge(
    state: &ClientState,
    path: &Path,
    size: u64,
    process_name: Option<&str>,
) -> Result<Judgement, String> {
    let bundle = state.policy.as_ref().ok_or("尚未同步策略（先执行 sync）")?;
    let path_text = path.to_string_lossy().to_string();
    let ctx = FileContext {
        path: &path_text,
        size,
        process_name,
    };

    let mut fallback: Option<Judgement> = None;
    for policy in &bundle.policy_sets {
        let decision = policy.evaluate(&ctx);
        if decision.action == Action::Encrypt {
            return Ok(Judgement {
                policy: policy.clone(),
                decision,
            });
        }
        if fallback.is_none() {
            fallback = Some(Judgement {
                policy: policy.clone(),
                decision,
            });
        }
    }
    fallback.ok_or_else(|| "策略包为空".to_string())
}

/// 加密单个文件（`合同.docx` → `合同.docx.ogd`）。
///
/// **安全顺序**（任何一步失败都不动原文件）：
/// 1. 规则判定（演练模式到此为止，**不碰磁盘**）；
/// 2. 加密到 `*.ogd.tmp`；
/// 3. **回读校验**新容器（分块 GCM + 尾部 SHA-256 全部通过）；
/// 4. 原子改名成 `.ogd`；
/// 5. 最后才处理原文件：移到回收区（默认）或删除。
pub fn encrypt_file(
    state: &ClientState,
    path: &Path,
    options: &EncryptOptions,
) -> Result<EncryptOutcome, String> {
    if !path.is_file() {
        return Err(format!("文件不存在：{}", path.display()));
    }
    let meta = std::fs::metadata(path).map_err(|e| format!("读取文件信息失败：{e}"))?;
    let judgement = judge(state, path, meta.len(), None)?;
    if judgement.decision.action != Action::Encrypt {
        return Err(format!(
            "规则判定为「{}」，不加密（规则：{}）",
            judgement.decision.action.as_str(),
            judgement.decision.rule_id.unwrap_or_else(|| "-".into())
        ));
    }

    let bundle = state.policy.as_ref().ok_or("策略未同步")?;
    let ext = bundle.container_ext.trim();
    let ext = if ext.is_empty() { "ogd" } else { ext };
    let output = PathBuf::from(format!("{}.{}", path.display(), ext));
    let rule_id = judgement.decision.rule_id.clone().unwrap_or_default();

    // 演练模式：只回报"将会发生什么"，磁盘零改动。
    if options.dry_run {
        return Ok(EncryptOutcome {
            output,
            policy_id: judgement.policy.id.clone(),
            rule_id,
            plain_size: meta.len(),
            applied: false,
        });
    }

    let key = policy_key(state, &judgement.policy.id)?;
    let header = Header {
        company: bundle.company.clone(),
        notice: bundle.notice.clone(),
        classification: bundle.classification.clone(),
        policy_id: judgement.policy.id.clone(),
        policy_version: judgement.policy.version,
        rule_id: rule_id.clone(),
        creator: dhrust::sys::machine::user_name(),
        client_id: state.client_id.clone(),
        created_at: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        original_name: file_name(path),
        original_size: meta.len(),
        plain_sha256: None,
    };

    let temp = PathBuf::from(format!("{}.tmp", output.display()));
    let summary = {
        let mut input = std::fs::File::open(path).map_err(|e| format!("打开原文件失败：{e}"))?;
        let mut out = std::fs::File::create(&temp)
            .map_err(|e| format!("创建临时文件失败（{}）：{e}", temp.display()))?;
        container::encrypt_stream(&key, &header, &mut input, &mut out)
            .map_err(|e| format!("加密失败：{e}"))?
    };

    // 回读校验：确认新容器能完整解出来，否则宁可不动原文件。
    if options.verify
        && let Err(e) = verify_container(&key, &temp)
    {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("新容器校验失败（原文件未做任何改动）：{e}"));
    }

    std::fs::rename(&temp, &output).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("生成容器失败（{}）：{e}", output.display())
    })?;

    // 原文件：优先移到回收区（可恢复），没配回收区才删。
    match &options.recovery_dir {
        Some(dir) => {
            if let Err(e) = std::fs::create_dir_all(dir) {
                dhrust::warn!(
                    "创建回收区失败（{e}）：原文件保留在原位（{}）",
                    path.display()
                );
            } else {
                let target = unique_path(dir, &file_name(path));
                if let Err(e) = std::fs::rename(path, &target) {
                    dhrust::warn!(
                        "原文件移入回收区失败（{e}）：原文件保留在原位（{}）",
                        path.display()
                    );
                }
            }
        }
        None => {
            if let Err(e) = std::fs::remove_file(path) {
                dhrust::warn!("原文件删除失败（{}）：{e}", path.display());
            }
        }
    }

    Ok(EncryptOutcome {
        output,
        policy_id: judgement.policy.id.clone(),
        rule_id,
        plain_size: summary.plain_size,
        applied: true,
    })
}

/// 回读校验：完整解密到 sink（验证头部/密钥/每块 GCM/尾部 SHA-256）。
fn verify_container(key: &[u8; crypto::KEY_LEN], path: &Path) -> Result<(), String> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("打开新容器失败：{e}"))?,
    );
    let mut sink = std::io::sink();
    container::decrypt_stream(key, &mut reader, &mut sink)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// 回收区内重名时追加序号（`合同.docx` → `合同(2).docx`）。
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = path
        .extension()
        .map(|value| format!(".{}", value.to_string_lossy()))
        .unwrap_or_default();
    for index in 2..1000 {
        let candidate = dir.join(format!("{stem}({index}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{stem}-{}{ext}", dhrust::random::hex(4)))
}

/// 解密容器到指定目录（按容器头记录的规则集取密钥）。
///
/// **离线兜底**：连续离线超过服务端下发的宽限期后拒绝解密（防止拔网线长期离线绕过吊销）；
/// 自动加密路径不经过本函数，离线时照样保护文件。
pub fn decrypt_file(state: &ClientState, path: &Path, out_dir: &Path) -> Result<PathBuf, String> {
    if let Some(reason) = state.offline_block_reason(chrono::Utc::now().timestamp()) {
        return Err(reason);
    }
    let file = std::fs::File::open(path).map_err(|e| format!("打开容器失败：{e}"))?;
    let mut reader = std::io::BufReader::new(file);
    let header = container::read_header(&mut reader).map_err(|e| format!("读取容器头失败：{e}"))?;

    let key = policy_key(state, &header.policy_id)?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("创建输出目录失败：{e}"))?;
    let output = out_dir.join(container::safe_output_name(&header));

    let mut input = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("重新打开容器失败：{e}"))?,
    );
    let mut out = std::fs::File::create(&output)
        .map_err(|e| format!("创建输出文件失败（{}）：{e}", output.display()))?;
    container::decrypt_stream(&key, &mut input, &mut out).map_err(|e| format!("解密失败：{e}"))?;
    Ok(output)
}

/// 解密到指定输出路径（受控打开用：文件名由调用方决定，便于识别会话）。
pub fn decrypt_to_file(state: &ClientState, container_path: &Path, output: &Path) -> Result<u64, String> {
    if let Some(reason) = state.offline_block_reason(chrono::Utc::now().timestamp()) {
        return Err(reason);
    }
    let mut input = std::io::BufReader::new(
        std::fs::File::open(container_path)
            .map_err(|e| format!("打开容器失败（{}）：{e}", container_path.display()))?,
    );
    let header =
        container::read_header(&mut input).map_err(|e| format!("读取容器头失败：{e}"))?;
    let key = policy_key(state, &header.policy_id)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建输出目录失败：{e}"))?;
    }

    let mut input = std::io::BufReader::new(
        std::fs::File::open(container_path).map_err(|e| format!("重新打开容器失败：{e}"))?,
    );
    let mut out = std::fs::File::create(output)
        .map_err(|e| format!("创建输出文件失败（{}）：{e}", output.display()))?;
    let summary =
        container::decrypt_stream(&key, &mut input, &mut out).map_err(|e| format!("解密失败：{e}"))?;
    Ok(summary.plain_size)
}

/// 回写：把受控临时目录里的**明文改动**重新加密回原容器（受控打开的保存闭环）。
///
/// 用**原容器同一把策略密钥**重封，并保留原明文头（公司/密级/规则/创建者），
/// 只更新大小与明文哈希；先写 `.tmp` 再原子替换，避免写到一半损坏原文件。
pub fn reseal_container(
    state: &ClientState,
    plain: &Path,
    container_path: &Path,
) -> Result<u64, String> {
    if !plain.is_file() {
        return Err(format!("临时明文不存在：{}", plain.display()));
    }
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(container_path)
            .map_err(|e| format!("打开原容器失败（{}）：{e}", container_path.display()))?,
    );
    let mut header =
        container::read_header(&mut reader).map_err(|e| format!("读取原容器头失败：{e}"))?;
    let key = policy_key(state, &header.policy_id)?;

    let meta = std::fs::metadata(plain).map_err(|e| format!("读取临时明文信息失败：{e}"))?;
    // 头部字段必须在加密前算好：加密后再改 header 不会生效（已被写进容器）。
    header.original_size = meta.len();
    header.plain_sha256 = Some(crypto::hex(&crypto::sha256(&std::fs::read(plain)
        .map_err(|e| format!("读取临时明文失败（{}）：{e}", plain.display()))?)));

    let temp = PathBuf::from(format!("{}.tmp", container_path.display()));
    let summary = {
        let mut input = std::fs::File::open(plain)
            .map_err(|e| format!("读取临时明文失败（{}）：{e}", plain.display()))?;
        let mut out = std::fs::File::create(&temp)
            .map_err(|e| format!("创建回写临时文件失败（{}）：{e}", temp.display()))?;
        container::encrypt_stream(&key, &header, &mut input, &mut out)
            .map_err(|e| format!("回写加密失败：{e}"))?
    };

    std::fs::rename(&temp, container_path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("回写替换失败（{}）：{e}", container_path.display())
    })?;
    Ok(summary.plain_size)
}

/// 受控打开：解密到受控临时目录并用系统默认程序打开。
pub fn open_file(state: &ClientState, path: &Path, temp_dir: &Path) -> Result<PathBuf, String> {
    let output = decrypt_file(state, path, temp_dir)?;
    launch_with_default_app(&output)?;
    Ok(output)
}

/// 用系统默认程序打开文件（受控打开会话复用）。
pub fn launch_with_default_app(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        // `start ""` 占位窗口标题，避免路径被当成标题。
        std::process::Command::new("cmd")
            .args(["/c", "start", "", &path.to_string_lossy()])
            .spawn()
            .map_err(|e| format!("启动默认程序失败：{e}"))?;
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|e| format!("启动默认程序失败：{e}"))?;
    }
    Ok(())
}

/// 取规则集对应的策略密钥（用终端令牌解包）。
fn policy_key(state: &ClientState, policy_id: &str) -> Result<[u8; crypto::KEY_LEN], String> {
    let bundle = state.policy.as_ref().ok_or("策略未同步")?;
    let wrapped = bundle
        .wrapped_keys
        .iter()
        .find(|item| item.policy_id == policy_id)
        .ok_or_else(|| format!("策略密钥缺失：{policy_id}"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&wrapped.wrapped_key)
        .map_err(|e| format!("策略密钥解码失败：{e}"))?;
    crypto::unwrap_for_client(&state.client_token, &bytes)
        .map_err(|e| format!("策略密钥解包失败：{e}"))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pek_outguard_core::protocol::{PolicyBundle, WrappedPolicyKey};
    use pek_outguard_core::rules::PolicySet;

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // 有意不用系统 TEMP：规则内置"临时目录软排除"，放 TEMP 会判定为放行。
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace")
            .join("target")
            .join("client-test");
        let dir = root.join(format!("{stamp}-{name}"));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    fn state_with_policy(token: &str) -> ClientState {
        let policy = PolicySet::builtin_default();
        // 与服务端一致：密钥由主密钥派生后用客户端令牌包裹。
        let master = [7u8; crypto::KEY_LEN];
        let key = crypto::derive_policy_key(&master, &policy.id, policy.key_version).expect("派生");
        let packed = crypto::wrap_for_client(token, &key).expect("包裹");
        let bundle = PolicyBundle {
            version: policy.version,
            policy_sets: vec![policy],
            wrapped_keys: vec![WrappedPolicyKey {
                policy_id: "default".into(),
                key_version: 1,
                wrapped_key: base64::engine::general_purpose::STANDARD.encode(packed),
            }],
            watch_roots: Vec::new(),
            exclude_paths: Vec::new(),
            container_ext: "ogd".into(),
            company: "示例科技有限公司".into(),
            notice: "本文件已加密".into(),
            classification: "内部".into(),
            allow_uninstall: false,
            offline_grace_days: 0,
            server_time: 0,
        };
        ClientState {
            client_id: "c-1".into(),
            client_token: token.into(),
            status: "active".into(),
            policy: Some(bundle),
            ..Default::default()
        }
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let dir = temp_dir("roundtrip");
        let source = dir.join("合同.docx");
        std::fs::write(&source, b"hello outguard").expect("写原文件");

        let state = state_with_policy("0011223344556677");
        let outcome = encrypt_file(&state, &source, &EncryptOptions { dry_run: false, recovery_dir: None, verify: true }).expect("加密成功");
        assert_eq!(outcome.rule_id, "office-pdf-cad");
        assert!(outcome.output.exists());
        assert!(!source.exists(), "加密后原文件必须删除");

        // 未装客户端：只能读到明文头
        let header = container::read_header(&mut std::io::BufReader::new(
            std::fs::File::open(&outcome.output).expect("打开容器"),
        ))
        .expect("读头");
        assert_eq!(header.company, "示例科技有限公司");

        let out_dir = dir.join("out");
        let plain = decrypt_file(&state, &outcome.output, &out_dir).expect("解密成功");
        assert_eq!(std::fs::read(&plain).expect("读明文"), b"hello outguard");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_matching_file_is_not_encrypted() {
        let dir = temp_dir("nomatch");
        let source = dir.join("notes.txt");
        std::fs::write(&source, b"x").expect("写文件");
        let state = state_with_policy("0011223344556677");
        let err = encrypt_file(&state, &source, &EncryptOptions { dry_run: false, recovery_dir: None, verify: true }).expect_err("txt 不该被加密");
        assert!(err.contains("不加密"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn offline_beyond_grace_denies_decrypt_but_still_encrypts() {
        let dir = temp_dir("offline");
        let state = state_with_policy("0011223344556677");

        // 正常联网状态：加密 → 解密可用。
        let first = dir.join("合同.docx");
        std::fs::write(&first, b"outguard offline").expect("写文件");
        let container_path = encrypt_file(&state, &first, &EncryptOptions { dry_run: false, recovery_dir: None, verify: true }).expect("加密成功").output;

        // 模拟“拔网线 30 天未上报”，且服务端下发的宽限为 7 天。
        let mut offline = state.clone();
        offline.last_online = chrono::Utc::now().timestamp() - 30 * 86_400;
        if let Some(bundle) = offline.policy.as_mut() {
            bundle.offline_grace_days = 7;
        }

        // 解密被拒，原因明确指出离线天数与宽限。
        let err = decrypt_file(&offline, &container_path, &dir.join("out"))
            .expect_err("超宽限必须拒绝解密");
        assert!(err.contains("离线 30 天"), "{err}");
        assert!(err.contains("7 天宽限"), "{err}");

        // 但自动加密不受影响：断网期间新文件照样要被保护。
        let second = dir.join("离线新建.docx");
        std::fs::write(&second, b"offline write").expect("写文件");
        let outcome = encrypt_file(&offline, &second, &EncryptOptions { dry_run: false, recovery_dir: None, verify: true }).expect("离线仍必须加密");
        assert!(outcome.output.exists());
        assert!(!second.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn judge_prefers_encrypt_across_policies() {
        let dir = temp_dir("judge");
        let source = dir.join("a.docx");
        std::fs::write(&source, b"x").expect("写文件");
        let mut state = state_with_policy("0011223344556677");
        if let Some(bundle) = state.policy.as_mut() {
            let mut plain = PolicySet::builtin_default();
            plain.id = "allow-all".into();
            plain.default_action = Action::Plaintext;
            plain.rules.clear();
            bundle.policy_sets.push(plain);
        }
        let judgement = judge(&state, &source, 1, None).expect("判定");
        assert_eq!(judgement.decision.action, Action::Encrypt);
        assert_eq!(judgement.policy.id, "default");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
