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
    /// 输出容器路径
    pub output: PathBuf,
    /// 生效规则集
    pub policy_id: String,
    /// 命中规则
    pub rule_id: String,
    /// 明文大小
    pub plain_size: u64,
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

/// 加密单个文件（`合同.docx` → `合同.docx.ogd`；成功后删除原文件）。
pub fn encrypt_file(state: &ClientState, path: &Path) -> Result<EncryptOutcome, String> {
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

    let key = policy_key(state, &judgement.policy.id)?;
    let bundle = state.policy.as_ref().ok_or("策略未同步")?;

    let header = Header {
        company: bundle.company.clone(),
        notice: bundle.notice.clone(),
        classification: bundle.classification.clone(),
        policy_id: judgement.policy.id.clone(),
        policy_version: judgement.policy.version,
        rule_id: judgement.decision.rule_id.clone().unwrap_or_default(),
        creator: dhrust::sys::machine::user_name(),
        client_id: state.client_id.clone(),
        created_at: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        original_name: file_name(path),
        original_size: meta.len(),
        plain_sha256: None,
    };

    let ext = bundle.container_ext.trim();
    let ext = if ext.is_empty() { "ogd" } else { ext };
    let output = PathBuf::from(format!("{}.{}", path.display(), ext));
    let temp = PathBuf::from(format!("{}.tmp", output.display()));

    let summary = {
        let mut input = std::fs::File::open(path).map_err(|e| format!("打开原文件失败：{e}"))?;
        let mut out = std::fs::File::create(&temp)
            .map_err(|e| format!("创建临时文件失败（{}）：{e}", temp.display()))?;
        container::encrypt_stream(&key, &header, &mut input, &mut out)
            .map_err(|e| format!("加密失败：{e}"))?
    };

    // ① 先原子落地容器，② 再删原文件（顺序颠倒会在改名失败时丢失原文件）。
    std::fs::rename(&temp, &output).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("生成容器失败（{}）：{e}", output.display())
    })?;
    if let Err(e) = std::fs::remove_file(path) {
        dhrust::warn!("原文件删除失败（{}）：{e}", path.display());
    }

    Ok(EncryptOutcome {
        output,
        policy_id: judgement.policy.id.clone(),
        rule_id: judgement.decision.rule_id.unwrap_or_default(),
        plain_size: summary.plain_size,
    })
}

/// 解密容器到指定目录（按容器头记录的规则集取密钥）。
pub fn decrypt_file(state: &ClientState, path: &Path, out_dir: &Path) -> Result<PathBuf, String> {
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

/// 受控打开：解密到受控临时目录并用系统默认程序打开。
pub fn open_file(state: &ClientState, path: &Path, temp_dir: &Path) -> Result<PathBuf, String> {
    let output = decrypt_file(state, path, temp_dir)?;
    launch_with_default_app(&output)?;
    Ok(output)
}

fn launch_with_default_app(path: &Path) -> Result<(), String> {
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
        let outcome = encrypt_file(&state, &source).expect("加密成功");
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
        let err = encrypt_file(&state, &source).expect_err("txt 不该被加密");
        assert!(err.contains("不加密"), "{err}");
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
