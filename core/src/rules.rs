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

/// 硬保护伪规则 ID：操作系统自身目录/文件，**任何规则都不能覆盖**。
///
/// 这是「不影响系统本身文件」的最后一道闸：即使管理员误配了指向 `C:\Windows` 的加密规则，
/// 也不会生效（会在审计里留下 `builtin:system` 记录）。
pub const HARD_PROTECT_RULE_ID: &str = "builtin:system";
/// 软排除伪规则 ID：临时目录/开发缓存，**在规则之前**即放行（避免通用扩展名规则误加密）。
pub const SOFT_EXCLUDE_RULE_ID: &str = "builtin:default-exclude";
/// 规则集排除路径的伪规则 ID。
pub const POLICY_EXCLUDE_RULE_ID: &str = "policy:exclude";

/// 兼容旧名（等价于硬保护）。
pub const BUILTIN_EXCLUDE_RULE_ID: &str = HARD_PROTECT_RULE_ID;

/// 系统保护级别（服务端配置 `watch_roots`、面板预览、客户端审计共用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// 不受保护（可被规则加密）。
    None,
    /// 硬保护：操作系统自身目录/文件，任何规则都不能加密。
    Hard,
    /// 软排除：临时目录/开发缓存，默认放行（且不可被通用规则覆盖）。
    Soft,
}

/// 硬保护：操作系统目录（段匹配）。
///
/// **不绑定 `C:`**：Windows 可安装在任意盘符（`D:\Windows`），也兼容老系统的 `WINNT`。
const HARD_EXCLUDE_SEGMENTS: &[&str] = &[
    "\\windows\\",
    "\\winnt\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
    "\\config.msi\\",
    "\\documents and settings\\",
];

/// 硬保护：盘符根下的系统目录（`X:\boot\`、`X:\efi\` 等）。
///
/// 仅对「盘符根」生效，所以 `D:\Work\boot\` 这类业务目录不受影响；UNC 共享盘不按此规则。
const HARD_DRIVE_ROOT_DIRS: &[&str] = &["boot", "efi", "recovery", "perflogs", "$winreagent"];

/// 硬保护：系统文件名（任意层级都不得加密）。
const HARD_FILE_NAMES: &[&str] = &[
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "dumpstack.log.tmp",
    "ntuser.dat",
    "ntuser.ini",
    "bootmgr",
    "bootnxt",
];

/// 软排除：临时目录与开发缓存（在规则之前放行，避免程序/编译被破坏）。
///
/// 有意**不包含 `ProgramData`**：它常放业务数据，需由具体规则决定（见测试
/// `programdata_is_rulable_when_explicitly_targeted`）。
const SOFT_EXCLUDE_SEGMENTS: &[&str] = &[
    "\\appdata\\local\\temp\\",
    "\\appdata\\local\\microsoft\\windows\\",
    "\\appdata\\local\\packages\\",
    "\\appdata\\local\\crashdumps\\",
    "\\.git\\",
    "\\.svn\\",
    "\\.hg\\",
    "\\node_modules\\",
    "\\__pycache__\\",
    "\\.vs\\",
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
    ///
    /// 顺序：硬保护 → 软排除 → 规则集排除路径 → 规则（优先级降序）→ 默认动作。
    /// 前两步保证「不影响系统本身文件」：系统目录与临时/缓存目录永远先放行，
    /// 连误配的加密规则都碰不到它们。
    pub fn evaluate(&self, ctx: &FileContext<'_>) -> Decision {
        let path_norm = normalize_path(ctx.path);
        let name = file_name(&path_norm);

        // 1. 硬保护：操作系统自身目录/文件（任何规则都不可覆盖）。
        if is_hard_protected(&path_norm) {
            return Decision {
                action: Action::Plaintext,
                rule_id: Some(HARD_PROTECT_RULE_ID.to_string()),
            };
        }

        // 2. 软排除：临时目录/开发缓存（在规则之前，防止通用扩展名规则误加密）。
        if is_soft_excluded(&path_norm) {
            return Decision {
                action: Action::Plaintext,
                rule_id: Some(SOFT_EXCLUDE_RULE_ID.to_string()),
            };
        }

        // 3. 规则集显式排除（管理员明确不放行的路径）。
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

        // 4. 规则（按优先级降序；同级保持声明顺序）。
        let mut ordered: Vec<&Rule> = self.rules.iter().collect();
        ordered.sort_by_key(|rule| std::cmp::Reverse(rule.priority));
        for rule in ordered {
            if rule.matches(&path_norm, name, ctx) {
                return Decision {
                    action: rule.action,
                    rule_id: Some(rule.id.clone()),
                };
            }
        }

        // 5. 规则集默认动作。
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

/// 判断路径是否命中硬保护（操作系统自身目录/文件）。
///
/// 供服务端配置 `watch_roots` 时排除、面板预览提示、客户端审计标识。
pub fn is_hard_protected(path: &str) -> bool {
    let path_norm = normalize_path(path);
    let lower = format!("{}\\", path_norm.to_ascii_lowercase());

    if HARD_EXCLUDE_SEGMENTS
        .iter()
        .any(|segment| lower.contains(segment))
    {
        return true;
    }

    // 盘符根下的系统目录（`X:\boot\...`）；UNC 共享盘不按此判定。
    if let Some(rest) = strip_drive_root(&path_norm) {
        let first = rest.split('\\').next().unwrap_or("").to_ascii_lowercase();
        if HARD_DRIVE_ROOT_DIRS.iter().any(|dir| first == *dir) {
            return true;
        }
    }

    let name = file_name(&path_norm).to_ascii_lowercase();
    HARD_FILE_NAMES.iter().any(|candidate| name == *candidate)
}

/// 判断路径是否命中软排除（临时目录/开发缓存）。
pub fn is_soft_excluded(path: &str) -> bool {
    let lower = format!("{}\\", normalize_path(path).to_ascii_lowercase());
    SOFT_EXCLUDE_SEGMENTS
        .iter()
        .any(|segment| lower.contains(segment))
}

/// 系统保护级别查询。
pub fn system_protection(path: &str) -> Protection {
    if is_hard_protected(path) {
        Protection::Hard
    } else if is_soft_excluded(path) {
        Protection::Soft
    } else {
        Protection::None
    }
}

/// 取盘符根之后的相对部分（`D:\boot\a` → `boot\a`）；非盘符路径返回 `None`。
fn strip_drive_root(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        Some(&path[3..])
    } else {
        None
    }
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
    fn hard_protected_system_paths_cannot_be_overridden() {
        // 故意写一条"想加密 Windows 目录"的规则：硬保护必须仍然放行。
        let mut encrypt = rule("encrypt", 10, Action::Encrypt);
        encrypt.extensions = vec!["dll".into()];
        encrypt.path_prefixes = vec!["C:\\Windows".into()];
        let policy = policy(vec![encrypt]);

        let decision = policy.evaluate(&ctx("C:\\Windows\\System32\\demo.dll", 10, None));
        assert_eq!(decision.action, Action::Plaintext);
        assert_eq!(decision.rule_id.as_deref(), Some(HARD_PROTECT_RULE_ID));
    }

    #[test]
    fn system_dirs_are_hard_protected_on_any_volume_and_legacy_name() {
        let mut encrypt = rule("any", 1, Action::Encrypt);
        encrypt.extensions = vec!["*".into()];
        let policy = policy(vec![encrypt]);

        for path in [
            "D:\\Windows\\System32\\a.txt",
            "C:\\WINNT\\system32\\a.txt",
            "C:\\Program Files\\App\\a.txt",
            "C:\\Program Files (x86)\\App\\a.txt",
            "C:\\$Recycle.Bin\\a.txt",
            "C:\\System Volume Information\\a.txt",
        ] {
            let decision = policy.evaluate(&ctx(path, 1, None));
            assert_eq!(
                decision.rule_id.as_deref(),
                Some(HARD_PROTECT_RULE_ID),
                "{path} 必须是硬保护"
            );
        }
    }

    #[test]
    fn drive_root_system_dirs_are_hard_protected() {
        for path in [
            "D:\\Boot\\BCD",
            "D:\\EFI\\Boot\\bootmgfw.efi",
            "D:\\Recovery\\a.txt",
        ] {
            assert!(is_hard_protected(path), "{path} 必须是硬保护");
        }
        // 业务目录里同名的 boot 不受影响（不在盘符根）。
        assert!(!is_hard_protected("D:\\Work\\boot\\readme.txt"));
        // UNC 共享盘上的 boot 目录是业务数据，不按盘符根处理。
        assert!(!is_hard_protected("\\\\nas\\share\\boot\\a.txt"));
    }

    #[test]
    fn system_files_are_hard_protected() {
        for path in [
            "C:\\pagefile.sys",
            "D:\\pagefile.sys",
            "C:\\hiberfil.sys",
            "C:\\Users\\a\\NTUSER.DAT",
            "C:\\Users\\a\\ntuser.ini",
        ] {
            assert!(is_hard_protected(path), "{path} 必须是硬保护");
        }
    }

    #[test]
    fn cache_dirs_are_soft_excluded_before_rules() {
        let mut encrypt = rule("docx", 10, Action::Encrypt);
        encrypt.extensions = vec!["docx".into()];
        let policy = policy(vec![encrypt]);

        let decision = policy.evaluate(&ctx(
            "C:\\Users\\a\\AppData\\Local\\Temp\\x.docx",
            1,
            None,
        ));
        assert_eq!(
            decision.action,
            Action::Plaintext,
            "临时目录不得被通用扩展名规则误加密"
        );
        assert_eq!(decision.rule_id.as_deref(), Some(SOFT_EXCLUDE_RULE_ID));

        let decision = policy.evaluate(&ctx("D:\\Work\\node_modules\\pkg\\a.docx", 1, None));
        assert_eq!(decision.action, Action::Plaintext);
        assert_eq!(decision.rule_id.as_deref(), Some(SOFT_EXCLUDE_RULE_ID));
    }

    #[test]
    fn programdata_is_rulable_when_explicitly_targeted() {
        // ProgramData 不内置排除（常放业务数据）：显式路径规则可以加密它。
        let mut encrypt = rule("export", 10, Action::Encrypt);
        encrypt.extensions = vec!["csv".into()];
        encrypt.path_prefixes = vec!["C:\\ProgramData\\MyApp\\export".into()];
        let policy = policy(vec![encrypt]);

        let decision = policy.evaluate(&ctx("C:\\ProgramData\\MyApp\\export\\a.csv", 1, None));
        assert_eq!(decision.action, Action::Encrypt);
        assert_eq!(decision.rule_id.as_deref(), Some("export"));
    }

    #[test]
    fn protection_levels_are_queryable() {
        assert_eq!(system_protection("C:\\Windows\\a.txt"), Protection::Hard);
        assert_eq!(
            system_protection("C:\\Users\\a\\AppData\\Local\\Temp\\a.txt"),
            Protection::Soft
        );
        assert_eq!(system_protection("D:\\Work\\a.docx"), Protection::None);
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
