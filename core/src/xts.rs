//! 透明加密用的块加密（M2 的地基）。
//!
//! # 为什么自己做，而不用 Windows CNG 的 XTS
//!
//! 实测：`BCRYPT_XTS_AES_ALGORITHM` 能打开，但 `BCryptEncrypt` 一律返回
//! `STATUS_INVALID_PARAMETER`（试了 16+ 种 key/数据单元/长度/属性位置组合）；
//! `ChainingModeCTR` 也不被支持。只剩 AES-ECB 是确定可用的底座。
//!
//! 所以这里用 AES-ECB 自己拼出"每块独立 tweak"的加密：
//!
//! ```text
//! tweak i = AES_ECB(key2, file_id[0..8] || block_index_be)
//! C i     = AES_ECB(key1, P i xor tweak i) xor tweak i
//! ```
//!
//! # 与 IEEE 1619 XTS 的差别（必须如实说明）
//!
//! 标准 XTS 的 tweak 是"初始 tweak 反复乘 α"得到的链。那样做**无法 O(1) 随机访问**
//! （文件越大，跳到后面的块要迭代越多次）。这里改成 `tweak = AES(key2, file_id || block_index)`：
//!
//! - **随机访问 O(1)**：任意偏移直接算出 tweak，这对 CAD/数据库这类随机读写是刚需；
//! - **安全性依据**：每个 (文件, 块) 的 tweak 都不同 ⇒ 等价于"每块独立随机 IV 的 ECB"，
//!   不会出现"相同明文块得到相同密文块"的模式泄露；
//! - **仍不提供完整性认证**（与 XTS / EFS / BitLocker 同级别）。篡改检测靠上层（OGD1 容器有 GCM）。
//!
//! # 长度
//!
//! 密文长度 = 明文长度（等长）。调用方需保证 `offset` 与数据长度都是 16 字节的倍数；
//! 文件尾部不足 16 字节的部分由调用方处理（见 [`XtsCipher::encrypt_tail`]）。

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

/// XTS-AES-256 的密钥长度：两个 AES-256 密钥。
pub const KEY_LEN: usize = 64;
/// 分组长度（AES 固定 16 字节）。
pub const BLOCK_LEN: usize = 16;

/// 文件身份（8 字节，参与 tweak 计算，避免不同文件同位置产生相同密文）。
pub type FileId = [u8; 8];

/// 每块独立 tweak 的 AES-256 加解密器。
pub struct XtsCipher {
    key1: Aes256,
    key2: Aes256,
}

impl XtsCipher {
    /// `key` 必须是 64 字节（两个 AES-256 密钥拼接）。
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != KEY_LEN {
            return Err(format!("XTS 密钥必须是 {KEY_LEN} 字节，实际 {}", key.len()));
        }
        Ok(Self {
            key1: Aes256::new_from_slice(&key[..32]).map_err(|e| format!("初始化 key1 失败：{e}"))?,
            key2: Aes256::new_from_slice(&key[32..]).map_err(|e| format!("初始化 key2 失败：{e}"))?,
        })
    }

    /// 计算第 `block_index` 块的 tweak。
    ///
    /// `tweak_input = file_id(8 字节) || block_index(8 字节，大端)`，再经 AES-ECB(key2) 加密。
    /// 这样不同文件、不同块都能 O(1) 得到互不相同的 tweak。
    fn tweak(&self, file_id: &FileId, block_index: u64) -> [u8; BLOCK_LEN] {
        let mut input = [0u8; BLOCK_LEN];
        input[..8].copy_from_slice(file_id);
        input[8..].copy_from_slice(&block_index.to_be_bytes());
        let mut block = GenericArray::clone_from_slice(&input);
        self.key2.encrypt_block(&mut block);
        block.into()
    }

    /// 原地加密若干**完整块**。`offset` 必须 16 字节对齐，`data.len()` 必须是 16 的倍数。
    pub fn encrypt_range(&self, file_id: &FileId, offset: u64, data: &mut [u8]) -> Result<(), String> {
        self.check(offset, data.len())?;
        let base = offset / BLOCK_LEN as u64;
        let (blocks, _) = data.as_chunks_mut::<BLOCK_LEN>();
        for (i, chunk) in blocks.iter_mut().enumerate() {
            let t = self.tweak(file_id, base + i as u64);
            let mut block = GenericArray::clone_from_slice(chunk);
            for j in 0..BLOCK_LEN {
                block[j] ^= t[j];
            }
            self.key1.encrypt_block(&mut block);
            for j in 0..BLOCK_LEN {
                chunk[j] = block[j] ^ t[j];
            }
        }
        Ok(())
    }

    /// 原地解密若干**完整块**（`encrypt_range` 的逆运算）。
    pub fn decrypt_range(&self, file_id: &FileId, offset: u64, data: &mut [u8]) -> Result<(), String> {
        self.check(offset, data.len())?;
        let base = offset / BLOCK_LEN as u64;
        let (blocks, _) = data.as_chunks_mut::<BLOCK_LEN>();
        for (i, chunk) in blocks.iter_mut().enumerate() {
            let t = self.tweak(file_id, base + i as u64);
            let mut block = GenericArray::clone_from_slice(chunk);
            for j in 0..BLOCK_LEN {
                block[j] ^= t[j];
            }
            self.key1.decrypt_block(&mut block);
            for j in 0..BLOCK_LEN {
                chunk[j] = block[j] ^ t[j];
            }
        }
        Ok(())
    }

    /// 文件尾部不足 16 字节的零头。
    ///
    /// 做法：用该块位置对应的 tweak 生成密钥流，只对前 `data.len()` 字节异或。
    /// 这样长度不变，且同一位置读写一致（驱动层的 read-modify-write 会保证对齐）。
    pub fn encrypt_tail(&self, file_id: &FileId, offset: u64, data: &mut [u8]) -> Result<(), String> {
        if !offset.is_multiple_of(BLOCK_LEN as u64) {
            return Err(format!("尾部偏移必须 16 字节对齐，实际 {offset}"));
        }
        if data.is_empty() {
            return Ok(());
        }
        if data.len() >= BLOCK_LEN {
            return Err(format!("尾部长度应小于 16 字节，实际 {}", data.len()));
        }
        let t = self.tweak(file_id, offset / BLOCK_LEN as u64);
        // 用 tweak 加密零块得到密钥流
        let mut stream = GenericArray::clone_from_slice(&t);
        self.key1.encrypt_block(&mut stream);
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= stream[i] ^ t[i];
        }
        Ok(())
    }

    /// 尾部解密（与 [`Self::encrypt_tail`] 相同：XOR 流对称）。
    pub fn decrypt_tail(&self, file_id: &FileId, offset: u64, data: &mut [u8]) -> Result<(), String> {
        self.encrypt_tail(file_id, offset, data)
    }

    fn check(&self, offset: u64, len: usize) -> Result<(), String> {
        if !offset.is_multiple_of(BLOCK_LEN as u64) {
            return Err(format!("偏移必须 16 字节对齐，实际 {offset}"));
        }
        if !len.is_multiple_of(BLOCK_LEN) {
            return Err(format!("长度必须是 16 的倍数，实际 {len}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        (0u8..64).collect()
    }

    fn file_id() -> FileId {
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(XtsCipher::new(&[0u8; 32]).is_err());
        assert!(XtsCipher::new(&[0u8; 63]).is_err());
        assert!(XtsCipher::new(&[0u8; 64]).is_ok());
    }

    #[test]
    fn roundtrip_multiple_blocks() {
        let cipher = XtsCipher::new(&test_key()).expect("初始化");
        let plain: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();

        let mut data = plain.clone();
        cipher.encrypt_range(&file_id(), 0, &mut data).expect("加密");
        assert_ne!(data, plain, "密文必须与明文不同");

        cipher.decrypt_range(&file_id(), 0, &mut data).expect("解密");
        assert_eq!(data, plain, "往返必须一致");
    }

    #[test]
    fn same_offset_different_file_id_gives_different_cipher() {
        let cipher = XtsCipher::new(&test_key()).expect("初始化");
        let mut a = vec![0u8; 64];
        let mut b = vec![0u8; 64];
        cipher.encrypt_range(&[0u8; 8], 0, &mut a).expect("加密 a");
        cipher.encrypt_range(&[1u8; 8], 0, &mut b).expect("加密 b");
        assert_ne!(a, b, "不同文件同位置不能产生相同密文");
    }

    #[test]
    fn random_access_matches_full_decrypt() {
        let cipher = XtsCipher::new(&test_key()).expect("初始化");
        let plain: Vec<u8> = (0..4096u32).map(|i| (i % 97) as u8).collect();

        let mut full = plain.clone();
        cipher.encrypt_range(&file_id(), 0, &mut full).expect("整体加密");

        // 单独解第 100 块（offset = 1600）
        let offset = 1600usize;
        let mut slice = full[offset..offset + 32].to_vec();
        cipher.decrypt_range(&file_id(), offset as u64, &mut slice).expect("分块解密");
        assert_eq!(slice, plain[offset..offset + 32], "分块解密必须与整体一致");
    }

    #[test]
    fn changing_one_byte_only_affects_its_block() {
        let cipher = XtsCipher::new(&test_key()).expect("初始化");
        let plain = vec![0u8; 64];
        let mut a = plain.clone();
        cipher.encrypt_range(&file_id(), 0, &mut a).expect("加密 a");

        let mut modified = plain.clone();
        modified[0] ^= 0x01; // 只改第一块第一个字节
        let mut b = modified.clone();
        cipher.encrypt_range(&file_id(), 0, &mut b).expect("加密 b");

        assert_ne!(a[..16], b[..16], "被改的块密文必须变化");
        assert_eq!(a[16..], b[16..], "其它块密文不应受影响");
    }

    #[test]
    fn rejects_unaligned_input() {
        let cipher = XtsCipher::new(&test_key()).expect("初始化");
        let mut data = vec![0u8; 17];
        assert!(cipher.encrypt_range(&file_id(), 0, &mut data).is_err(), "长度非 16 倍数应报错");
        let mut data2 = vec![0u8; 16];
        assert!(cipher.encrypt_range(&file_id(), 8, &mut data2).is_err(), "偏移未对齐应报错");
    }

    #[test]
    fn tail_roundtrip_keeps_length() {
        let cipher = XtsCipher::new(&test_key()).expect("初始化");
        let plain = vec![0xABu8; 7];
        let mut data = plain.clone();
        cipher.encrypt_tail(&file_id(), 1024, &mut data).expect("加密尾部");
        assert_eq!(data.len(), 7, "尾部长度必须不变");
        assert_ne!(data, plain, "尾部也要真的加密");
        cipher.decrypt_tail(&file_id(), 1024, &mut data).expect("解密尾部");
        assert_eq!(data, plain, "尾部往返一致");
    }

    /// **交叉验证**：与内核侧（Windows CNG 的 AES-256-ECB）独立实现逐字节对齐。
    ///
    /// 参考值由 `driver/xref-xts.ps1` 用 `bcrypt.dll` 独立计算得出：
    /// key = 000102...3f(64B)、file_id = 1122334455667788。
    ///
    /// 这条测试是"文件绝不锁死"的保险：驱动用 CNG、救援工具用 Rust，
    /// 一旦两边算法漂移（改 tweak 排布、改异或顺序、换字节序），这里立刻失败。
    #[test]
    fn matches_windows_cng_reference_vectors() {
        let cipher = XtsCipher::new(&test_key()).expect("初始化");
        let id = file_id();

        // tweak：AES_ECB(key2, file_id || block_index_be)
        assert_eq!(
            hex(&cipher.tweak(&id, 0)),
            "b2d86a4b8145cb41b78ce0654b0183e0",
            "block 0 的 tweak 与 CNG 不一致"
        );
        assert_eq!(
            hex(&cipher.tweak(&id, 1)),
            "b8bbec34d9537e3d6e3f46c98cfe998b",
            "block 1 的 tweak 与 CNG 不一致"
        );

        // 密文：块 0 明文全 0；块 1 明文 0001..0f
        let mut b0 = vec![0u8; 16];
        cipher.encrypt_range(&id, 0, &mut b0).expect("加密块 0");
        assert_eq!(
            hex(&b0),
            "3c7c2c4da3ac6d528a970f90b393d252",
            "块 0 密文与 CNG 不一致（明文全 0）"
        );

        let mut b1: Vec<u8> = (0u8..16).collect();
        cipher.encrypt_range(&id, 16, &mut b1).expect("加密块 1");
        assert_eq!(
            hex(&b1),
            "6471017c2835b8e68b8b1b4b71c6e7e4",
            "块 1 密文与 CNG 不一致（明文 0001..0f）"
        );

        // 随机访问：块 4（offset=64）单独解/加密，须与 CNG 一致
        let mut b4: Vec<u8> = (0..16u8).map(|i| 0xA0u8.wrapping_add(i)).collect();
        cipher.encrypt_range(&id, 64, &mut b4).expect("加密块 4");
        assert_eq!(
            hex(&b4),
            "8072b0db5099ed87b560c56a0128bb1f",
            "块 4 密文与 CNG 不一致（随机访问路径）"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
