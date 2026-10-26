//! 规则引擎：**Server 与 Client 同一份实现**。
//!
//! 判定顺序（双端一致）：
//! 1. 内置系统排除（Windows 目录 / Program Files / 回收站 / 系统卷信息 / Temp）
//! 2. 规则集 `exclude_paths`（受控临时目录、客户端自身数据目录等）
//! 3. 规则按 `priority` 降序、同级按声明顺序匹配（首个命中即返回）
//! 4. 都不命中 → 规则集 `default_action`
//!
//! 匹配语义：路径/扩展名/进程名大小写不敏感（Windows 口径）；路径前缀按**目录边界**比较
//! （`D:\Work` 不会命中 `D:\Work2`）；文件名支持 `*`/`?` 通配（复用 `dhrust::io::wildcard_match`）。

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 内置系统排除的伪规则 ID（审计里便于区分"被系统保护规则放行"）。
pub const BUILTIN_EXCLUDE_RULE_ID: &str = "builtin:system";
/// 规则集排除路径的伪规则 ID。
pub const POLICY_EXCLUDE_RULE_ID: &str = "policy:exclude";

/// 内置排除的路径片段（小写比较；两侧带分隔符以避免误伤同名目录）。
const BUILTIN_EXCLUDE_SEGMENTS: &[&str] = &[
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\appdata\\local\\temp\\",
];

/// 命中后的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// 强制加密（文件落盘即变为容器）。
    Encrypt,
    /// 明确放行（白名单）。
    Plaintext,
    /// 禁止落盘（阻断写入）。
    BlockWrite,
    /// 仅记录审计，不做处理。
    Audit,
}

impl Action {
    /// 稳定的字符串形式（审计/面板展示）。
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Encrypt => "encrypt",
            Action::Plaintext => "plaintext",
            Action::BlockWrite => "block_write",
            Action::Audit => "audit",
        }
    }
}

/// 一条规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    /// 规则 ID（规则集内唯一）。
    pub id: String,
    /// 优先级（数值大者优先）。
    #[serde(default)]
    pub priority: i32,
    /// 命中后的动作。
    pub action: Action,
    /// 扩展名（不含点，小写；`*` = 任意）。空 = 不限。
    #[serde(default)]
    pub extensions: Vec<String>,
    /// 文件名通配（如 `报价*.xlsx`）。空 = 不限。
    #[serde(default)]
    pub name_patterns: Vec<String>,
    /// 路径前缀（如 `D:\Work`、`\\nas\项目`）。空 = 不限。
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    /// 来源进程名（如 `winword.exe`；`*` = 任意）。空 = 不限。
    #[serde(default)]
    pub process_names: Vec<String>,
    /// 最小文件大小（字节，含）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    /// 最大文件大小（字节，含）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
}

impl Rule {
    /// 判断是否命中（调用方已排除系统路径与规则集排除路径）。
    fn matches(&self, path_norm: &str, name: &str, ctx: &FileContext<'_>) -> bool {
        if let Some(min) = self.min_size
            && ctx.size < min
        {
            return false;
        }
        if let Some(max) = self.max_size
            && ctx.size > max
        {
            return false;
        }

        if !self.extensions.is_empty() {
            let ext = extension_of(name);
            if !self
                .extensions
                .iter()
                .any(|pattern| pattern == "*" || pattern.eq_ignore_ascii_case(&ext))
            {
                return false;
            }
        }

        if !self.name_patterns.is_empty()
            && !self
                .name_patterns
                .iter()
                .any(|pattern| dhrust::io::wildcard_match(pattern, name))
        {
            return false;
        }

        if !self.path_prefixes.is_empty()
            && !self
                .path_prefixes
                .iter()
                .any(|prefix| path_has_prefix(path_norm, prefix))
        {
            return false;
        }

        if !self.process_names.is_empty() {
            let Some(process_name) = ctx.process_name else {
                return false;
            };
            if !self
                .process_names
                .iter()
                .any(|pattern| pattern == "*" || process_name.eq_ignore_ascii_case(pattern))
            {
                return false;
            }
        }

        true
    }
}

/// 规则集：可被多个终端组/终端/用户共享（多对多绑定在服务端）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySet {
    /// 规则集 ID。
    pub id: String,
    /// 名称（面板展示）。
    pub name: String,
    /// 版本号（每次改规则递增；终端必须回执）。
    pub version: u32,
    /// 策略密钥版本（轮换时递增；旧文件按容器头记录的版本解密）。
    pub key_version: u32,
    /// 都不命中时的动作（默认放行，避免误伤）。
    #[serde(default = "default_action")]
    pub default_action: Action,
    /// 排除路径（受控临时目录、客户端数据目录等）。
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// 规则明细。
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn default_action() -> Action {
    Action::Plaintext
}

/// 判定输入（服务端"规则预览"与客户端"实际执行"共用）。
#[derive(Debug, Clone, Copy)]
pub struct FileContext<'a> {
    /// 绝对路径。
    pub path: &'a str,
    /// 文件大小（字节）。
    pub size: u64,
    /// 写入该文件的进程名（可选；未知时按"不限定进程"的规则处理）。
    pub process_name: Option<&'a str>,
}

/// 判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// 动作。
    pub action: Action,
    /// 命中的规则 ID（内置/排除路径使用伪规则 ID；默认动作为 `None`）。
    pub rule_id: Option<String>,
}

impl Decision {
    /// 是否需要加密。
    pub fn should_encrypt(&self) -> bool {
        self.action == Action::Encrypt
    }
}

impl PolicySet {
    /// 执行判定。
    pub fn evaluate(&self, ctx: &FileContext<'_>) -> Decision {
        let path_norm = normalize_path(ctx.path);
        let name = file_name(&path_norm);

        if is_builtin_excluded(&path_norm) {
            return Decision {
                action: Action::Plaintext,
                rule_id: Some(BUILTIN_EXCLUDE_RULE_ID.to_string()),
            };
        }

        if self
            .exclude_paths
            .iter()
            .any(|prefix| path_has_prefix(&path_norm, prefix))
        {
            return Decision {
                action: Action::Plaintext,
                rule_id: Some(POLICY_EXCLUDE_RULE_ID.to_string()),
            };
        }

        let mut ordered: Vec<&Rule> = self.rules.iter().collect();
        // 稳定排序：同优先级保持声明顺序。
        ordered.sort_by_key(|rule| std::cmp::Reverse(rule.priority));
        for rule in ordered {
            if rule.matches(&path_norm, name, ctx) {
                return Decision {
                    action: rule.action,
                    rule_id: Some(rule.id.clone()),
                };
            }
        }

        Decision {
            action: self.default_action,
            rule_id: None,
        }
    }

    /// 保存前校验（服务端调用）：规则 ID 唯一、大小区间合法。
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(Error::Rule("规则集 ID 不能为空".into()));
        }
        if self.key_version == 0 {
            return Err(Error::Rule("规则集密钥版本必须从 1 开始".into()));
        }

        let mut seen = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(Error::Rule("规则 ID 不能为空".into()));
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(Error::Rule(format!("规则 ID 重复：{}", rule.id)));
            }
            if let (Some(min), Some(max)) = (rule.min_size, rule.max_size)
                && min > max
            {
                return Err(Error::Rule(format!(
                    "规则 {} 的大小区间非法：{min} > {max}",
                    rule.id
                )));
            }
        }
        Ok(())
    }
}

/// 规范化路径：统一分隔符、剥离 `\\?\` 长路径前缀、去尾部多余分隔符。
pub fn normalize_path(raw: &str) -> String {
    let mut path = raw.trim().replace('/', "\\");
    if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        path = format!("\\\\{rest}");
    } else if let Some(rest) = path.strip_prefix("\\\\?\\") {
        path = rest.to_string();
    }
    while path.len() > 3 && path.ends_with('\\') {
        path.pop();
    }
    path
}

/// 路径是否位于某前缀之下（按目录边界，大小写不敏感）。
pub fn path_has_prefix(path_norm: &str, prefix: &str) -> bool {
    let prefix_norm = normalize_path(prefix);
    if prefix_norm.is_empty() {
        return true;
    }
    let path = path_norm.to_ascii_lowercase();
    let prefix = prefix_norm.to_ascii_lowercase();
    if path == prefix {
        return true;
    }
    // 前缀本身可能已带尾分隔符（如根目录 `D:\`）。
    if prefix.ends_with('\\') {
        return path.starts_with(&prefix);
    }
    path.starts_with(&format!("{prefix}\\"))
}

/// 内置系统排除。
fn is_builtin_excluded(path_norm: &str) -> bool {
    let lower = format!("{}\\", path_norm.to_ascii_lowercase());
    BUILTIN_EXCLUDE_SEGMENTS
        .iter()
        .any(|segment| lower.contains(segment))
}

fn file_name(path_norm: &str) -> &str {
    path_norm.rsplit('\\').next().unwrap_or(path_norm)
}

fn extension_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, priority: i32, action: Action) -> Rule {
        Rule {
            id: id.into(),
            priority,
            action,
            extensions: Vec::new(),
            name_patterns: Vec::new(),
            path_prefixes: Vec::new(),
            process_names: Vec::new(),
            min_size: None,
            max_size: None,
        }
    }

    fn policy(rules: Vec<Rule>) -> PolicySet {
        PolicySet {
            id: "p1".into(),
            name: "默认规则".into(),
            version: 1,
            key_version: 1,
            default_action: Action::Plaintext,
            exclude_paths: vec!["D:\\Work\\temp".into()],
            rules,
        }
    }

    fn ctx<'a>(path: &'a str, size: u64, process_name: Option<&'a str>) -> FileContext<'a> {
        FileContext {
            path,
            size,
            process_name,
        }
    }

    #[test]
    fn extension_hit() {
        let mut docx = rule("docx", 10, Action::Encrypt);
        docx.extensions = vec!["docx".into(), "xlsx".into()];
        let policy = policy(vec![docx]);

        let decision = policy.evaluate(&ctx("D:\\Work\\合同.DOCX", 100, None));
        assert_eq!(decision.action, Action::Encrypt);
        assert_eq!(decision.rule_id.as_deref(), Some("docx"));
        assert!(decision.should_encrypt());

        let decision = policy.evaluate(&ctx("D:\\Work\\notes.txt", 100, None));
        assert_eq!(decision.action, Action::Plaintext);
        assert_eq!(decision.rule_id, None);
    }

    #[test]
    fn priority_wins_over_declaration_order() {
        let mut allow = rule("allow", 100, Action::Plaintext);
        allow.name_patterns = vec!["公开*".into()];
        let mut encrypt = rule("encrypt", 10, Action::Encrypt);
        encrypt.extensions = vec!["docx".into()];

        let policy = policy(vec![encrypt, allow]);
        let decision = policy.evaluate(&ctx("D:\\Work\\公开说明.docx", 10, None));
        assert_eq!(decision.action, Action::Plaintext);
        assert_eq!(decision.rule_id.as_deref(), Some("allow"));
    }

    #[test]
    fn exclude_path_beats_rules() {
        let mut encrypt = rule("encrypt", 10, Action::Encrypt);
        encrypt.extensions = vec!["docx".into()];
        let policy = policy(vec![encrypt]);

        let decision = policy.evaluate(&ctx("D:\\Work\\temp\\a.docx", 10, None));
        assert_eq!(decision.action, Action::Plaintext);
        assert_eq!(decision.rule_id.as_deref(), Some(POLICY_EXCLUDE_RULE_ID));
    }

    #[test]
    fn builtin_system_paths_are_excluded() {
        let mut encrypt = rule("encrypt", 10, Action::Encrypt);
        encrypt.extensions = vec!["dll".into()];
        let policy = policy(vec![encrypt]);

        let decision = policy.evaluate(&ctx("C:\\Windows\\System32\\demo.dll", 10, None));
        assert_eq!(decision.action, Action::Plaintext);
        assert_eq!(decision.rule_id.as_deref(), Some(BUILTIN_EXCLUDE_RULE_ID));

        let decision = policy.evaluate(&ctx(
            "C:\\Users\\a\\AppData\\Local\\Temp\\x.docx",
            10,
            None,
        ));
        assert_eq!(decision.action, Action::Plaintext);
        assert_eq!(decision.rule_id.as_deref(), Some(BUILTIN_EXCLUDE_RULE_ID));
    }

    #[test]
    fn directory_boundary_is_respected() {
        let mut encrypt = rule("encrypt", 10, Action::Encrypt);
        encrypt.path_prefixes = vec!["D:\\Work".into()];
        let policy = policy(vec![encrypt]);

        assert_eq!(
            policy.evaluate(&ctx("D:\\Work\\a.docx", 1, None)).action,
            Action::Encrypt
        );
        assert_eq!(
            policy.evaluate(&ctx("D:\\Work2\\a.docx", 1, None)).action,
            Action::Plaintext,
            "D:\\Work 不得命中 D:\\Work2"
        );
    }

    #[test]
    fn process_filter() {
        let mut encrypt = rule("office", 10, Action::Encrypt);
        encrypt.extensions = vec!["docx".into()];
        encrypt.process_names = vec!["winword.exe".into(), "wps.exe".into()];
        let policy = policy(vec![encrypt]);

        assert_eq!(
            policy
                .evaluate(&ctx("D:\\Work\\a.docx", 1, Some("WINWORD.EXE")))
                .action,
            Action::Encrypt
        );
        assert_eq!(
            policy
                .evaluate(&ctx("D:\\Work\\a.docx", 1, Some("notepad.exe")))
                .action,
            Action::Plaintext
        );
        assert_eq!(
            policy.evaluate(&ctx("D:\\Work\\a.docx", 1, None)).action,
            Action::Plaintext,
            "进程未知时不命中进程限定的规则"
        );
    }

    #[test]
    fn size_range_filter() {
        let mut encrypt = rule("big", 10, Action::Encrypt);
        encrypt.extensions = vec!["pdf".into()];
        encrypt.min_size = Some(1024);
        encrypt.max_size = Some(10 * 1024);
        let policy = policy(vec![encrypt]);

        assert_eq!(
            policy.evaluate(&ctx("D:\\a.pdf", 100, None)).action,
            Action::Plaintext
        );
        assert_eq!(
            policy.evaluate(&ctx("D:\\a.pdf", 2048, None)).action,
            Action::Encrypt
        );
        assert_eq!(
            policy.evaluate(&ctx("D:\\a.pdf", 100 * 1024, None)).action,
            Action::Plaintext
        );
    }

    #[test]
    fn wildcard_name_and_extension() {
        let mut any_ext = rule("any-ext", 10, Action::Encrypt);
        any_ext.extensions = vec!["*".into()];
        any_ext.name_patterns = vec!["报价*".into()];
        let policy = policy(vec![any_ext]);

        assert_eq!(
            policy
                .evaluate(&ctx("D:\\Work\\报价单-2026.xlsx", 1, None))
                .action,
            Action::Encrypt
        );
        assert_eq!(
            policy
                .evaluate(&ctx("D:\\Work\\合同-2026.xlsx", 1, None))
                .action,
            Action::Plaintext
        );
    }

    #[test]
    fn long_path_prefix_and_unified_separators() {
        let mut encrypt = rule("encrypt", 10, Action::Encrypt);
        encrypt.path_prefixes = vec!["D:/Work/secret".into()];
        let policy = policy(vec![encrypt]);

        assert_eq!(
            policy
                .evaluate(&ctx("\\\\?\\D:\\Work\\secret\\a.docx", 1, None))
                .action,
            Action::Encrypt
        );
    }

    #[test]
    fn default_action_can_be_encrypt() {
        let mut policy = policy(Vec::new());
        policy.default_action = Action::Encrypt;
        assert_eq!(
            policy.evaluate(&ctx("D:\\Work\\a.txt", 1, None)).action,
            Action::Encrypt
        );
    }

    #[test]
    fn validate_catches_duplicates_and_bad_ranges() {
        let mut a = rule("dup", 1, Action::Encrypt);
        a.extensions = vec!["docx".into()];
        let mut b = rule("dup", 2, Action::Plaintext);
        b.min_size = Some(100);
        b.max_size = Some(10);

        let duplicated = policy(vec![a, b]);
        assert!(duplicated.validate().is_err(), "重复 ID 必须被拒");

        let mut bad_version = policy(vec![rule("ok", 1, Action::Encrypt)]);
        bad_version.key_version = 0;
        assert!(bad_version.validate().is_err(), "密钥版本 0 必须被拒");
    }
}
