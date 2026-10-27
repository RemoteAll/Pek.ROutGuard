//! **侧表**：路径 → 文件身份（file_id）。
//!
//! # 解决两个真实风险
//!
//! 1. **A1（第 19 轮审计）**：ADS 里的校验和是无密钥的 SHA-256，有写权限的人改掉 `file_id`
//!    再重算校验和就能绕过。侧表独立记一份，**发现不一致时可以判断哪份是对的**；
//! 2. **ADS 丢失**：FAT32/exFAT/U 盘、部分备份与同步工具都会丢掉 ADS。
//!    文件还在、内容还是密文，但没有 `file_id` 就解不开——侧表是唯一的指望。
//!
//! # 为什么不用数据库
//!
//! 一个纯查找表不值得引入 SQLite：要建连接池、写 ORM 样板、还要考虑库文件损坏后的修复。
//! 这里用**按路径哈希分片的小文本文件**：
//!
//! - 256 个分片，每个文件几千行，查找只读一个分片（内存与 IO 都很轻）；
//! - 写入用"临时文件 + 原子替换"，断电不会写出半个文件；
//! - 纯文本，出问题时运维肉眼就能看、能手改。
//!
//! 10 万文件大约 256 个文件各 400 行，单次查找读 ~40KB，完全够用。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pek_outguard_core::meta::FileMeta;

/// 分片数（按路径哈希的低 8 位切分）
const SHARDS: usize = 256;

/// 一条索引记录
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// 文件绝对路径（统一成小写比较，见 [`normalize_key`]）
    pub path: String,
    /// file_id
    pub file_id: [u8; 8],
    /// 记录时间（Unix 秒）
    pub created_at: u64,
}

impl IndexEntry {
    fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}",
            self.file_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            self.created_at,
            self.path
        )
    }

    /// 解析一行。格式错了返回 None（跳过该行，不炸整个索引——救援时宁可少一条也不能读不出来）。
    fn from_line(line: &str) -> Option<Self> {
        let mut parts = line.splitn(3, '\t');
        let id_hex = parts.next()?;
        let created = parts.next()?;
        let path = parts.next()?;
        if id_hex.len() != 16 {
            return None;
        }
        let mut file_id = [0u8; 8];
        for (i, chunk) in id_hex.as_bytes().chunks(2).enumerate() {
            if i >= 8 {
                return None;
            }
            let s = std::str::from_utf8(chunk).ok()?;
            file_id[i] = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self {
            path: path.to_string(),
            file_id,
            created_at: created.parse().ok()?,
        })
    }
}

/// 路径归一化：统一分隔符、统一小写。
///
/// Windows 路径大小写不敏感，而在索引里混用大小写会出现"同一文件两条记录"，
/// 反而让救援时无法判断哪条是真的。
pub fn normalize_key(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

/// 侧表
pub struct FileIndex {
    dir: PathBuf,
}

impl FileIndex {
    /// `dir` 通常是 `{客户端数据目录}/DriverIndex`
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
        }
    }

    /// 该路径属于哪个分片文件
    fn shard_of(&self, key: &str) -> PathBuf {
        // 用 FNV-1a 散列（简单、稳定、不依赖 std 的 DefaultHasher 实现细节）
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in key.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        let idx = (hash % SHARDS as u64) as usize;
        self.dir.join(format!("{idx:02x}.idx"))
    }

    /// 读一个分片
    fn load_shard(&self, shard: &Path) -> Result<BTreeMap<String, IndexEntry>, String> {
        let mut map = BTreeMap::new();
        let text = match std::fs::read_to_string(shard) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(map),
            Err(e) => return Err(format!("读取索引分片失败（{}）：{e}", shard.display())),
        };
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(entry) = IndexEntry::from_line(line) {
                map.insert(entry.path.clone(), entry);
            }
            // 坏行直接跳过：索引是"辅助证据"，不能因为它坏了就让主流程失败
        }
        Ok(map)
    }

    /// 原子写一个分片
    fn store_shard(&self, shard: &Path, map: &BTreeMap<String, IndexEntry>) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("创建索引目录失败（{}）：{e}", self.dir.display()))?;
        let mut text = String::with_capacity(map.len() * 80);
        for entry in map.values() {
            text.push_str(&entry.to_line());
            text.push('\n');
        }
        let temp = shard.with_extension("idx-tmp");
        std::fs::write(&temp, text.as_bytes())
            .map_err(|e| format!("写索引临时文件失败（{}）：{e}", temp.display()))?;
        dhrust::io::safe_replace_file(&temp, shard).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            format!("替换索引分片失败（{}）：{e}", shard.display())
        })
    }

    /// 查询某个路径的 file_id
    pub fn get(&self, path: &Path) -> Result<Option<[u8; 8]>, String> {
        let key = normalize_key(path);
        let shard = self.shard_of(&key);
        Ok(self.load_shard(&shard)?.get(&key).map(|e| e.file_id))
    }

    /// 记录一个文件（覆盖同名记录）
    pub fn put(&self, path: &Path, meta: &FileMeta) -> Result<(), String> {
        let key = normalize_key(path);
        let shard = self.shard_of(&key);
        let mut map = self.load_shard(&shard)?;
        map.insert(
            key.clone(),
            IndexEntry {
                path: key,
                file_id: meta.file_id,
                created_at: meta.created_at,
            },
        );
        self.store_shard(&shard, &map)
    }

    /// 删除一个记录
    pub fn remove(&self, path: &Path) -> Result<(), String> {
        let key = normalize_key(path);
        let shard = self.shard_of(&key);
        let mut map = self.load_shard(&shard)?;
        if map.remove(&key).is_some() {
            self.store_shard(&shard, &map)?;
        }
        Ok(())
    }

    /// 按 file_id 反查路径（救援用：只知道 file_id 时要找出是哪个文件）。
    ///
    /// 需要扫全部分片，只在救援/诊断时调用，不进热路径。
    pub fn find_by_file_id(&self, file_id: &[u8; 8]) -> Result<Vec<PathBuf>, String> {
        let mut out = Vec::new();
        for shard_index in 0..SHARDS {
            let shard = self.dir.join(format!("{shard_index:02x}.idx"));
            let map = self.load_shard(&shard)?;
            for entry in map.values() {
                if &entry.file_id == file_id {
                    out.push(PathBuf::from(&entry.path));
                }
            }
        }
        Ok(out)
    }

    /// 总条数与占用的分片数（诊断用）
    pub fn stats(&self) -> Result<(usize, usize), String> {
        let mut total = 0;
        let mut shards = 0;
        for shard_index in 0..SHARDS {
            let shard = self.dir.join(format!("{shard_index:02x}.idx"));
            let map = self.load_shard(&shard)?;
            if !map.is_empty() {
                shards += 1;
                total += map.len();
            }
        }
        Ok((total, shards))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oug-index-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    fn meta(id: u8) -> FileMeta {
        FileMeta {
            file_id: [id; 8],
            created_at: 1_700_000_000 + u64::from(id),
            flags: pek_outguard_core::meta::FLAG_ENCRYPTED,
        }
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = temp_dir();
        let index = FileIndex::new(dir.join("idx"));
        let path = Path::new(r"D:\机密\方案.docx");

        assert_eq!(index.get(path).expect("查"), None, "未记录时应为 None");
        index.put(path, &meta(0x11)).expect("写");
        assert_eq!(index.get(path).expect("查"), Some([0x11; 8]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_lookup_is_case_and_separator_insensitive() {
        let dir = temp_dir();
        let index = FileIndex::new(dir.join("idx"));
        index
            .put(Path::new(r"D:\机密\方案.docx"), &meta(0x22))
            .expect("写");

        // 大小写不同、分隔符不同，都应命中同一条
        assert_eq!(
            index.get(Path::new(r"d:\机密\方案.docx")).expect("查"),
            Some([0x22; 8])
        );
        assert_eq!(
            index.get(Path::new("D:/机密/方案.docx")).expect("查"),
            Some([0x22; 8]),
            "正斜杠应等价于反斜杠"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrite_keeps_single_record() {
        let dir = temp_dir();
        let index = FileIndex::new(dir.join("idx"));
        let path = Path::new(r"D:\a.docx");
        index.put(path, &meta(1)).expect("写");
        index.put(path, &meta(2)).expect("覆盖");
        assert_eq!(index.get(path).expect("查"), Some([2; 8]));
        assert_eq!(index.stats().expect("统计").0, 1, "覆盖不应产生两条记录");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_deletes_record() {
        let dir = temp_dir();
        let index = FileIndex::new(dir.join("idx"));
        let path = Path::new(r"D:\b.docx");
        index.put(path, &meta(3)).expect("写");
        index.remove(path).expect("删");
        assert_eq!(index.get(path).expect("查"), None);
        // 删不存在的也不报错
        index.remove(path).expect("再删不报错");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_by_file_id_scans_all_shards() {
        let dir = temp_dir();
        let index = FileIndex::new(dir.join("idx"));
        // 造 200 条，确保散落在多个分片
        for i in 0..200u16 {
            let path = PathBuf::from(format!(r"D:\资料\文件{i}.docx"));
            let mut m = meta(0x40);
            m.file_id = [(i & 0xFF) as u8, (i >> 8) as u8, 0, 0, 0, 0, 0, 0];
            index.put(&path, &m).expect("写");
        }
        assert!(index.stats().expect("统计").1 > 1, "应散落在多个分片");

        let found = index.find_by_file_id(&[7, 0, 0, 0, 0, 0, 0, 0]).expect("反查");
        assert_eq!(found.len(), 1, "应唯一命中");
        assert!(found[0].to_string_lossy().contains("文件7.docx"));

        assert!(index
            .find_by_file_id(&[0xFF; 8])
            .expect("反查")
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_lines_are_skipped_not_fatal() {
        let dir = temp_dir();
        let index_dir = dir.join("idx");
        std::fs::create_dir_all(&index_dir).expect("建");
        let index = FileIndex::new(index_dir.clone());

        let path = Path::new(r"D:\c.docx");
        index.put(path, &meta(4)).expect("写");

        // 往同名分片里塞坏行
        let key = normalize_key(path);
        let shard = index.shard_of(&key);
        let mut text = std::fs::read_to_string(&shard).expect("读");
        text.push_str("这不是一行合法记录\n");
        text.push_str("zzzz\tnotanumber\tD:\\x\n");
        std::fs::write(&shard, text).expect("写");

        // 坏行不影响好记录
        assert_eq!(index.get(path).expect("查"), Some([4; 8]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn entry_line_roundtrip() {
        let entry = IndexEntry {
            path: r"d:\机密\a.docx".into(),
            file_id: [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            created_at: 1_700_000_123,
        };
        let line = entry.to_line();
        let back = IndexEntry::from_line(&line).expect("解析");
        assert_eq!(back, entry);
    }

    #[test]
    fn normalize_handles_mixed_separators() {
        assert_eq!(
            normalize_key(Path::new(r"D:\A\B.TXT")),
            normalize_key(Path::new("d:/a/b.txt"))
        );
    }
}
