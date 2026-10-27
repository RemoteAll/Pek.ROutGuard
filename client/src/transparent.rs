//! **用户态透明加密引擎**：把一个普通文件当成"读写明文"来用，落在磁盘上的永远是等长密文。
//!
//! # 为什么先写这个（而不是直接写内核）
//!
//! 内核里的加解密只做对一次是不够的——它面对的是：非对齐偏移、跨块读写、尾部不足 16 字节、
//! 追加、截断、零长文件、缓存与直接 I/O 双路径……每一条写错都是**用户数据损坏**。
//! 而驱动一旦加载，任何 bug 都只能在蓝屏或文件打不开时才暴露。
//!
//! 所以这里用纯用户态把它做成**可完整测试的黄金参照实现**：
//! - 所有边界条件在这里跑单测，全部可复现、可断言；
//! - 内核实现完成后，可拿同一批用例逐字节对拍；
//! - 这段代码本身也能用（救援工具、离线加解密、测试夹具）。
//!
//! # 关键设计：块对齐读写
//!
//! XTS 的 tweak 依赖**块序号**，所以任何写操作都必须以 16 字节为单位落到磁盘：
//! 未对齐的写要"读出受影响的块 → 解密 → 改 → 加密 → 写回"。
//!
//! 还有一个容易漏的坑：**尾部不足 16 字节的处理方式与完整块不同**
//! （完整块走 `encrypt_range`，尾部走 `encrypt_tail` 的 XOR 流）。
//! 因此把文件从 100 字节截断到 50 字节时，**必须把原来属于完整块的那部分重新按 tail 加密**，
//! 否则读回来就是乱码。这一点由 `truncate` 的测试守住。

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pek_outguard_core::xts::{BLOCK_LEN, FileId, XtsCipher};

/// 块大小（16 字节，与 XTS 一致）
const BLOCK: u64 = BLOCK_LEN as u64;

/// 把 `len` 向上取整到块边界
fn align_up(len: u64) -> u64 {
    len.div_ceil(BLOCK) * BLOCK
}

/// 把 `len` 向下取整到块边界
fn align_down(len: u64) -> u64 {
    len / BLOCK * BLOCK
}

/// 一个以"明文视角"读写的文件。
///
/// 磁盘上是密文，长度与明文**完全相等**——这是透明加密能对应用无感的前提。
pub struct TransparentFile {
    path: PathBuf,
    file: std::fs::File,
    cipher: XtsCipher,
    file_id: FileId,
    /// 明文长度（= 磁盘文件长度）
    plain_len: u64,
}

impl TransparentFile {
    /// 打开一个已有的加密文件。
    pub fn open(path: &Path, cipher: XtsCipher, file_id: FileId) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("打开失败（{}）：{e}", path.display()))?;
        let plain_len = file
            .metadata()
            .map_err(|e| format!("读取文件信息失败（{}）：{e}", path.display()))?
            .len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            cipher,
            file_id,
            plain_len,
        })
    }

    /// 创建一个新的空加密文件（已存在则报错，绝不覆盖）。
    pub fn create(path: &Path, cipher: XtsCipher, file_id: FileId) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("创建失败（{}）：{e}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            cipher,
            file_id,
            plain_len: 0,
        })
    }

    /// 明文长度
    pub fn len(&self) -> u64 {
        self.plain_len
    }

    /// 是否为空文件
    pub fn is_empty(&self) -> bool {
        self.plain_len == 0
    }

    /// 读明文 `[offset, offset + buf.len())`，返回实际读到的字节数（到文件末尾为止）。
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, String> {
        if buf.is_empty() || offset >= self.plain_len {
            return Ok(0);
        }
        let want = ((self.plain_len - offset) as usize).min(buf.len());

        // 只读覆盖目标范围的**块对齐区间**，避免整文件读取
        let aligned_start = align_down(offset);
        let aligned_end = align_up(offset + want as u64).min(self.plain_len);
        let span = (aligned_end - aligned_start) as usize;

        let mut raw = vec![0u8; span];
        self.file
            .seek(SeekFrom::Start(aligned_start))
            .map_err(|e| format!("定位失败：{e}"))?;
        self.file
            .read_exact(&mut raw)
            .map_err(|e| format!("读取密文失败（{}）：{e}", self.path.display()))?;

        self.decrypt_span(aligned_start, &mut raw, self.plain_len)?;

        let from = (offset - aligned_start) as usize;
        buf[..want].copy_from_slice(&raw[from..from + want]);
        Ok(want)
    }

    /// 读整个文件的明文。
    pub fn read_all(&mut self) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; self.plain_len as usize];
        let n = self.read_at(0, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// 写明文到 `[offset, offset + data.len())`，必要时扩展文件。
    ///
    /// 未对齐的写会先读出受影响的块、改完再写回——**任何写都不会破坏相邻字节**。
    /// 写完会把文件精确截到明文长度：块对齐写会把文件撑到 16 的倍数，
    /// 而透明加密的硬指标是"磁盘长度 == 明文长度"。
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset + data.len() as u64;
        let new_len = self.plain_len.max(end);

        let aligned_start = align_down(offset);
        // 写回范围不能超过明文长度：超出部分是"填充"，写它既浪费又会把尾部撑成 16 字节
        let write_end = align_up(end).min(new_len).max(end);
        let span = (write_end - aligned_start) as usize;

        // 读出这段现有密文；超出原文件末尾的部分按"明文零"补齐
        let mut raw = vec![0u8; span];
        let existing_end = write_end.min(self.plain_len);
        if existing_end > aligned_start {
            let existing = (existing_end - aligned_start) as usize;
            self.file
                .seek(SeekFrom::Start(aligned_start))
                .map_err(|e| format!("定位失败：{e}"))?;
            self.file
                .read_exact(&mut raw[..existing])
                .map_err(|e| format!("读取密文失败（{}）：{e}", self.path.display()))?;
            self.decrypt_span(aligned_start, &mut raw[..existing], self.plain_len)?;
            // 剩余部分保持 0（明文零）
            for byte in raw.iter_mut().skip(existing) {
                *byte = 0;
            }
        }

        let from = (offset - aligned_start) as usize;
        raw[from..from + data.len()].copy_from_slice(data);

        // 用**新的**明文长度决定哪些字节走 range、哪些走 tail
        self.encrypt_span(aligned_start, &mut raw, new_len)?;

        self.file
            .seek(SeekFrom::Start(aligned_start))
            .map_err(|e| format!("定位失败：{e}"))?;
        self.file
            .write_all(&raw)
            .map_err(|e| format!("写入密文失败（{}）：{e}", self.path.display()))?;

        self.plain_len = new_len;
        // 块对齐写会把文件撑大，必须缩回明文长度（否则磁盘长度 != 明文长度）
        if self
            .file
            .metadata()
            .map(|m| m.len() > new_len)
            .unwrap_or(false)
        {
            self.file
                .set_len(new_len)
                .map_err(|e| format!("调整长度失败（{}）：{e}", self.path.display()))?;
        }
        Ok(())
    }

    /// 追加到末尾。
    pub fn append(&mut self, data: &[u8]) -> Result<(), String> {
        self.write_at(self.plain_len, data)
    }

    /// 截断/扩展到 `new_len`。
    ///
    /// 缩短到非块边界时，**必须把最后一个完整块转成 tail 加密**：
    /// 完整块走 `encrypt_range`、尾部走 `encrypt_tail`，两者算法不同；
    /// 直接 `set_len` 会让被截断的那几个字节用错误的方式解读 → 读出来是乱码。
    pub fn truncate(&mut self, new_len: u64) -> Result<(), String> {
        if new_len == self.plain_len {
            return Ok(());
        }
        if new_len < self.plain_len {
            let tail_start = align_down(new_len);
            let old_tail_len = self.plain_len - tail_start;

            // 原文件在 tail_start 之后还有内容：重写这段，让它在新的明文长度下
            // 按正确的方式加密（可能从"完整块"变成"尾部"，也可能反之）
            if old_tail_len > 0 {
                let mut buf = vec![0u8; old_tail_len as usize];
                self.file
                    .seek(SeekFrom::Start(tail_start))
                    .map_err(|e| format!("定位失败：{e}"))?;
                self.file
                    .read_exact(&mut buf)
                    .map_err(|e| format!("读取密文失败（{}）：{e}", self.path.display()))?;
                // 用旧的明文长度解密
                self.decrypt_span(tail_start, &mut buf, self.plain_len)?;

                buf.truncate((new_len - tail_start) as usize);
                // 用新的明文长度加密
                self.encrypt_span(tail_start, &mut buf, new_len)?;

                self.file
                    .seek(SeekFrom::Start(tail_start))
                    .map_err(|e| format!("定位失败：{e}"))?;
                self.file
                    .write_all(&buf)
                    .map_err(|e| format!("写入密文失败（{}）：{e}", self.path.display()))?;
            }

            self.file
                .set_len(new_len)
                .map_err(|e| format!("截断失败（{}）：{e}", self.path.display()))?;
            self.plain_len = new_len;
        } else {
            // 扩展：通过 write_at 写零，保证新区域也是正确加密的
            let zeros = vec![0u8; (new_len - self.plain_len) as usize];
            self.write_at(self.plain_len, &zeros)?;
        }
        Ok(())
    }

    /// 刷盘。
    pub fn sync(&mut self) -> Result<(), String> {
        self.file
            .sync_all()
            .map_err(|e| format!("刷盘失败：{e}"))
    }

    /// 解密一个磁盘上的连续区间（`offset` 必须 16 字节对齐）。
    ///
    /// **划分依据是明文长度，不是 buf 长度**：只有整块落在 `plain_len` 以内的部分
    /// 才是"完整块"（走 range），明文末尾那截不足 16 字节的走 tail（XOR 流）。
    /// 两者密文完全不同，判错哪一个都会读出乱码。
    fn decrypt_span(&self, offset: u64, buf: &mut [u8], plain_len: u64) -> Result<(), String> {
        debug_assert!(offset.is_multiple_of(BLOCK), "区间起点必须块对齐");
        self.split_and(offset, buf, plain_len, false)
    }

    /// 加密一个连续区间，划分规则与 [`Self::decrypt_span`] 一致。
    fn encrypt_span(&self, offset: u64, buf: &mut [u8], plain_len: u64) -> Result<(), String> {
        debug_assert!(offset.is_multiple_of(BLOCK), "区间起点必须块对齐");
        self.split_and(offset, buf, plain_len, true)
    }

    /// **完整块 / 尾部**的统一划分与处理。
    fn split_and(
        &self,
        offset: u64,
        buf: &mut [u8],
        plain_len: u64,
        encrypt: bool,
    ) -> Result<(), String> {
        let full_end = align_down(plain_len).max(offset);
        let range_end = offset + buf.len() as u64;
        let full_stop = range_end.min(full_end);
        if full_stop > offset {
            let n = (full_stop - offset) as usize;
            if encrypt {
                self.cipher
                    .encrypt_range(&self.file_id, offset, &mut buf[..n])?;
            } else {
                self.cipher
                    .decrypt_range(&self.file_id, offset, &mut buf[..n])?;
            }
        }
        if range_end > full_stop {
            let from = (full_stop - offset) as usize;
            if encrypt {
                self.cipher
                    .encrypt_tail(&self.file_id, full_stop, &mut buf[from..])?;
            } else {
                self.cipher
                    .decrypt_tail(&self.file_id, full_stop, &mut buf[from..])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oug-transparent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("建目录");
        dir
    }

    fn cipher() -> XtsCipher {
        XtsCipher::new(&(0u8..64).collect::<Vec<u8>>()).expect("cipher")
    }

    const FID: FileId = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

    /// 建一个已有内容的文件（用透明引擎写入），返回路径
    fn make_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = TransparentFile::create(&path, cipher(), FID).expect("创建");
        f.write_at(0, content).expect("写");
        f.sync().expect("刷盘");
        path
    }

    #[test]
    fn write_then_read_roundtrip_various_lengths() {
        let dir = temp_dir();
        // 覆盖：空 / 短于一块 / 正好一块 / 一块多一字节 / 多块
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100, 4096, 4097] {
            let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let path = make_file(&dir, &format!("f{len}.bin"), &content);

            // 磁盘长度必须与明文完全相等（透明加密的硬指标）
            assert_eq!(
                std::fs::metadata(&path).expect("stat").len(),
                len as u64,
                "长度 {len}：磁盘长度必须等于明文长度"
            );

            let mut f = TransparentFile::open(&path, cipher(), FID).expect("打开");
            assert_eq!(f.read_all().expect("读"), content, "长度 {len}：内容必须一致");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unaligned_reads_do_not_corrupt_neighbors() {
        let dir = temp_dir();
        let content: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let path = make_file(&dir, "a.bin", &content);

        let mut f = TransparentFile::open(&path, cipher(), FID).expect("打开");
        // 各种非对齐起点/长度
        for (off, len) in [(0usize, 1usize), (1, 1), (3, 17), (15, 2), (16, 1), (31, 33), (199, 1)] {
            let mut buf = vec![0u8; len];
            let n = f.read_at(off as u64, &mut buf).expect("读");
            assert_eq!(n, len, "偏移 {off} 长度 {len}：应读满");
            assert_eq!(
                buf,
                &content[off..off + len],
                "偏移 {off} 长度 {len}：读到的必须是原文"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unaligned_write_preserves_surrounding_bytes() {
        let dir = temp_dir();
        let mut content: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
        let path = make_file(&dir, "b.bin", &content);

        let mut f = TransparentFile::open(&path, cipher(), FID).expect("打开");
        // 写 3 个字节到偏移 5（完全落在第一块内部）
        f.write_at(5, b"XYZ").expect("写");
        content[5..8].copy_from_slice(b"XYZ");

        // 跨块的写
        f.write_at(14, b"ABCDE").expect("写");
        content[14..19].copy_from_slice(b"ABCDE");

        assert_eq!(f.read_all().expect("读"), content);

        // 重新打开确认已落盘
        drop(f);
        let mut f = TransparentFile::open(&path, cipher(), FID).expect("重开");
        assert_eq!(f.read_all().expect("读"), content);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_extends_file() {
        let dir = temp_dir();
        let path = dir.join("c.bin");
        let mut f = TransparentFile::create(&path, cipher(), FID).expect("创建");
        let part2 = "世界".as_bytes();
        f.append(b"hello").expect("追加");
        f.append(part2).expect("追加");
        let mut expected = b"hello".to_vec();
        expected.extend_from_slice(part2);
        assert_eq!(f.len(), expected.len() as u64);
        assert_eq!(f.read_all().expect("读"), expected);

        // 磁盘长度 = 明文长度（不是块对齐长度！）
        assert_eq!(
            std::fs::metadata(&path).expect("stat").len(),
            expected.len() as u64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_to_block_boundary_and_beyond() {
        let dir = temp_dir();
        let content: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
        let path = make_file(&dir, "d.bin", &content);

        // 截断到 64（块边界）
        let mut f = TransparentFile::open(&path, cipher(), FID).expect("打开");
        f.truncate(64).expect("截断");
        assert_eq!(f.len(), 64);
        assert_eq!(f.read_all().expect("读"), &content[..64]);
        drop(f);

        // 重新打开仍然可读（关键：截断后必须还能解出来）
        let mut f = TransparentFile::open(&path, cipher(), FID).expect("重开");
        assert_eq!(f.read_all().expect("读"), &content[..64]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_to_non_block_boundary_keeps_plaintext_readable() {
        // 这是最容易写错的边界：把 100 字节截断到 50 字节时，
        // 偏移 48..50 原本属于"完整块"，截断后变成"尾部"，加密方式不同。
        // 如果只 set_len 不重新按 tail 加密，读回来就是乱码。
        let dir = temp_dir();
        let content: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
        let path = make_file(&dir, "e.bin", &content);

        let mut f = TransparentFile::open(&path, cipher(), FID).expect("打开");
        f.truncate(50).expect("截断到 50（非块边界）");
        assert_eq!(f.len(), 50);
        assert_eq!(
            f.read_all().expect("读"),
            &content[..50],
            "截断到非块边界后必须仍能正确解出前 50 字节"
        );
        drop(f);

        let mut f = TransparentFile::open(&path, cipher(), FID).expect("重开");
        assert_eq!(f.read_all().expect("读"), &content[..50]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_to_zero_and_regrow() {
        let dir = temp_dir();
        let content: Vec<u8> = (0..40u32).map(|i| i as u8).collect();
        let path = make_file(&dir, "f.bin", &content);

        let mut f = TransparentFile::open(&path, cipher(), FID).expect("打开");
        f.truncate(0).expect("截断到 0");
        assert_eq!(f.len(), 0);
        assert_eq!(f.read_all().expect("读"), Vec::<u8>::new());
        // 再长回来：新区域必须读出 0
        f.truncate(20).expect("扩展");
        assert_eq!(f.len(), 20);
        assert_eq!(f.read_all().expect("读"), vec![0u8; 20]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_beyond_end_zero_fills_gap() {
        let dir = temp_dir();
        let path = dir.join("g.bin");
        let mut f = TransparentFile::create(&path, cipher(), FID).expect("创建");
        f.write_at(10, b"TAIL").expect("写");
        assert_eq!(f.len(), 14);
        let mut expected = vec![0u8; 10];
        expected.extend_from_slice(b"TAIL");
        assert_eq!(f.read_all().expect("读"), expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_content_is_ciphertext_not_plaintext() {
        let dir = temp_dir();
        let plain = b"CONFIDENTIAL-COMPANY-SECRET-DO-NOT-LEAK-0123456789".to_vec();
        let path = make_file(&dir, "h.bin", &plain);

        let on_disk = std::fs::read(&path).expect("读盘");
        assert_eq!(on_disk.len(), plain.len(), "等长");
        assert_ne!(on_disk, plain, "磁盘上必须是密文");
        // 明文片段不应出现在密文里
        assert!(
            !on_disk.windows(8).any(|w| w == b"CONFIDE"),
            "密文中不得出现明文片段"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_at_eof_returns_zero() {
        let dir = temp_dir();
        let path = make_file(&dir, "i.bin", b"12345");
        let mut f = TransparentFile::open(&path, cipher(), FID).expect("打开");
        let mut buf = [0u8; 8];
        assert_eq!(f.read_at(5, &mut buf).expect("读"), 0, "在末尾读应返回 0");
        assert_eq!(f.read_at(100, &mut buf).expect("读"), 0, "越过末尾应返回 0");
        // 从中间读到末尾前：只读回剩余部分
        assert_eq!(f.read_at(3, &mut buf).expect("读"), 2);
        assert_eq!(&buf[..2], b"45");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_never_overwrites_existing() {
        let dir = temp_dir();
        make_file(&dir, "j.bin", b"keep me");
        let err = TransparentFile::create(&dir.join("j.bin"), cipher(), FID)
            .err()
            .expect("已存在必须报错");
        assert!(err.contains("创建失败"), "错误信息应可定位，实际：{err}");
        // 原内容不受影响
        let mut f = TransparentFile::open(&dir.join("j.bin"), cipher(), FID).expect("打开");
        assert_eq!(f.read_all().expect("读"), b"keep me");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn different_file_ids_produce_different_ciphertext() {
        let dir = temp_dir();
        let content = vec![0u8; 64];
        let a = dir.join("k1.bin");
        let b = dir.join("k2.bin");

        let mut fa = TransparentFile::create(&a, cipher(), [0u8; 8]).expect("建");
        fa.write_at(0, &content).expect("写");
        drop(fa);
        let mut fb = TransparentFile::create(&b, cipher(), [1u8; 8]).expect("建");
        fb.write_at(0, &content).expect("写");
        drop(fb);

        assert_ne!(
            std::fs::read(&a).expect("读"),
            std::fs::read(&b).expect("读"),
            "相同明文 + 不同 file_id 必须产生不同密文"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_file_survives_reopen() {
        let dir = temp_dir();
        let path = dir.join("l.bin");
        let f = TransparentFile::create(&path, cipher(), FID).expect("创建");
        drop(f);
        assert_eq!(std::fs::metadata(&path).expect("stat").len(), 0);
        let f = TransparentFile::open(&path, cipher(), FID).expect("重开");
        assert_eq!(f.len(), 0);
        assert!(f.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
