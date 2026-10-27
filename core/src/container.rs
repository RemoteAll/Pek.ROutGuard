//! `OGD1` 加密容器：流式加密/解密 + 明文头（未装客户端也能看到公司防泄密提示）。
//!
//! 字节布局（小端）：
//!
//! ```text
//! 偏移        长度        内容
//! 0           4          Magic  "OGD1"
//! 4           2          formatVersion = 1
//! 6           2          flags（保留，首版必须为 0）
//! 8           4          headerLen (≤ 64 KiB)
//! 12          H          Header JSON（UTF-8，明文）
//! 12+H        4          keyBlockLen
//! 16+H        K          KeyBlock：nonce(12) || AES-256-GCM(DEK)，AAD = SHA-256(Header JSON)
//! 16+H+K      4          chunkSize (1 MiB 默认，≤ 16 MiB)
//! 20+H+K      8          noncePrefix
//! 28+H+K      4+N        [分块]：u32 密文长度 + 密文（tag 附尾）
//! …           4          END 标记（u32 = 0）
//! 末尾        32         SHA-256（覆盖 END 之前的全部字节）
//! ```
//!
//! 设计取舍：
//! - **KeyBlock 前置**：解密要先拿 DEK 才能流式解密；放尾部会多一次全量 IO。
//! - **AAD 绑定头部**：改动公司名/密级/规则等任一字段都会导致解密失败。
//! - **每块独立 GCM tag**：单块损坏不影响其它块定位；流式内存占用 = 1 个块。
//! - **明文头不含密钥材料**：只有元数据与提示语，供未装客户端时的提示与审计。

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{self, GCM_TAG_LEN, KEY_LEN};
use crate::error::{Error, Result};

/// 容器魔数。
pub const MAGIC: [u8; 4] = *b"OGD1";
/// 当前格式版本。
pub const FORMAT_VERSION: u16 = 1;
/// 默认分块大小（1 MiB）。
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
/// 允许的最大分块（防止恶意文件让客户端申请超大内存）。
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
/// 明文头长度上限。
pub const MAX_HEADER_LEN: u32 = 64 * 1024;
/// 尾部摘要长度。
pub const FOOTER_LEN: usize = 32;

/// 明文头部：未装客户端用记事本打开即可看到公司信息与防泄密提示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// 公司名称（防泄密提示第一条）。
    pub company: String,
    /// 提示语（如"本文件已加密，仅限安装 OutGuard 客户端的授权电脑打开…"）。
    pub notice: String,
    /// 密级（公开/内部/秘密/机密；由规则集配置）。
    #[serde(default)]
    pub classification: String,
    /// 生成该文件时生效的规则集。
    pub policy_id: String,
    /// 规则集版本（用于审计与"文件来自哪个版本策略"）。
    pub policy_version: u32,
    /// 命中的规则 ID（未命中规则时为空串）。
    #[serde(default)]
    pub rule_id: String,
    /// 创建者（终端登录用户）。
    #[serde(default)]
    pub creator: String,
    /// 终端 ID。
    #[serde(default)]
    pub client_id: String,
    /// 创建时间（ISO-8601 文本，由调用方格式化）。
    pub created_at: String,
    /// 原始文件名（客户端打开时按原名落地）。
    pub original_name: String,
    /// 原始文件大小（字节）。
    pub original_size: u64,
    /// 原始文件 SHA-256（十六进制；可选，加密前计算）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_sha256: Option<String>,
}

/// 加密结果摘要（调用方落审计）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptSummary {
    /// 分块数量。
    pub chunk_count: u64,
    /// 明文总字节数。
    pub plain_size: u64,
    /// 明文 SHA-256。
    pub plain_sha256: [u8; 32],
    /// 容器 SHA-256（不含尾部摘要本身）。
    pub cipher_sha256: [u8; 32],
}

/// 解密结果摘要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptSummary {
    /// 容器头。
    pub header: Header,
    /// 明文总字节数。
    pub plain_size: u64,
    /// 容器 SHA-256（已通过尾部校验）。
    pub cipher_sha256: [u8; 32],
}

/// 判断给定字节是否为容器魔数（读文件前 4 字节即可）。
pub fn is_container_magic(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC
}

/// 生成安全的落地文件名（防路径穿越；空名回退 `unnamed`）。
pub fn safe_output_name(header: &Header) -> String {
    let name = dhrust::io::sanitize_file_name(header.original_name.trim());
    if name.trim().is_empty() {
        "unnamed".to_string()
    } else {
        name
    }
}

/// 头部序列化（校验长度上限）。
pub fn header_bytes(header: &Header) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(header)
        .map_err(|e| Error::Format(format!("头部序列化失败：{e}")))?;
    if json.is_empty() {
        return Err(Error::Format("头部为空".into()));
    }
    if json.len() > MAX_HEADER_LEN as usize {
        return Err(Error::Format(format!(
            "头部过大：{} 字节（上限 {MAX_HEADER_LEN}）",
            json.len()
        )));
    }
    Ok(json)
}

/// 只读取容器头（不解密主体）。用于"预览/提示/服务端识别"。
pub fn read_header<R: Read>(input: &mut R) -> Result<Header> {
    let header_json = read_header_json(input)?;
    serde_json::from_slice(&header_json)
        .map_err(|e| Error::Format(format!("头部 JSON 解析失败：{e}")))
}

fn read_header_json<R: Read>(input: &mut R) -> Result<Vec<u8>> {
    let mut fixed = [0u8; 12];
    input
        .read_exact(&mut fixed)
        .map_err(|e| Error::Format(format!("读取容器头失败（文件被截断？）：{e}")))?;

    if fixed[..4] != MAGIC {
        return Err(Error::Format("不是 OutGuard 容器（魔数不匹配）".into()));
    }
    let version = u16::from_le_bytes([fixed[4], fixed[5]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format(format!(
            "不支持的容器版本：{version}（本程序支持 {FORMAT_VERSION}）"
        )));
    }
    let flags = u16::from_le_bytes([fixed[6], fixed[7]]);
    if flags != 0 {
        return Err(Error::Format(format!("容器标志位非法：0x{flags:04x}")));
    }
    let header_len = u32::from_le_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(Error::Format(format!("头部长度非法：{header_len}")));
    }

    let mut header_json = vec![0u8; header_len as usize];
    input
        .read_exact(&mut header_json)
        .map_err(|e| Error::Format(format!("读取头部 JSON 失败：{e}")))?;
    Ok(header_json)
}

/// 流式加密（默认 1 MiB 分块）。
pub fn encrypt_stream<R: Read, W: Write>(
    kek: &[u8; KEY_LEN],
    header: &Header,
    plain: &mut R,
    out: &mut W,
) -> Result<EncryptSummary> {
    encrypt_stream_with_chunk(kek, header, DEFAULT_CHUNK_SIZE, plain, out)
}

/// 流式加密（指定分块大小；测试用小分块覆盖多块路径）。
pub fn encrypt_stream_with_chunk<R: Read, W: Write>(
    kek: &[u8; KEY_LEN],
    header: &Header,
    chunk_size: u32,
    plain: &mut R,
    out: &mut W,
) -> Result<EncryptSummary> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::Format(format!(
            "分块大小非法：{chunk_size}（1..={MAX_CHUNK_SIZE}）"
        )));
    }

    let header_json = header_bytes(header)?;
    let header_hash = crypto::sha256(&header_json);

    // 每文件随机 DEK + nonce 前缀，用策略密钥包裹后写入 KeyBlock。
    let dek: [u8; KEY_LEN] = crypto::random_array();
    let key_block = crypto::wrap_key(kek, &dek, &header_hash)?;
    let nonce_prefix: [u8; 8] = crypto::random_array();

    let mut buffer = vec![0u8; chunk_size as usize];
    let mut plain_hasher = Sha256::new();
    let mut plain_size: u64 = 0;
    let mut chunk_count: u64 = 0;

    // 作用域限定 writer 的借用：块结束后才能写尾部摘要。
    let cipher_sha256: [u8; 32] = {
        let mut writer = HashingWriter::new(out);
        writer.write_all(&MAGIC)?;
        writer.write_all(&FORMAT_VERSION.to_le_bytes())?;
        writer.write_all(&0u16.to_le_bytes())?;
        writer.write_all(&(header_json.len() as u32).to_le_bytes())?;
        writer.write_all(&header_json)?;
        writer.write_all(&(key_block.len() as u32).to_le_bytes())?;
        writer.write_all(&key_block)?;
        writer.write_all(&chunk_size.to_le_bytes())?;
        writer.write_all(&nonce_prefix)?;

        loop {
            let read = read_full(plain, &mut buffer)?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            plain_hasher.update(chunk);
            plain_size += read as u64;

            let nonce = crypto::chunk_nonce(&nonce_prefix, chunk_count);
            let ciphertext = crypto::encrypt_chunk(&dek, &nonce, chunk, &header_hash)?;
            writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
            writer.write_all(&ciphertext)?;
            chunk_count += 1;
        }

        writer.write_all(&0u32.to_le_bytes())?; // END
        let digest = writer.digest();
        writer.flush()?;
        digest
    };

    out.write_all(&cipher_sha256)?;
    out.flush()?;

    Ok(EncryptSummary {
        chunk_count,
        plain_size,
        plain_sha256: plain_hasher.finalize().into(),
        cipher_sha256,
    })
}

/// 流式解密（自动校验尾部 SHA-256）。
pub fn decrypt_stream<R: Read, W: Write>(
    kek: &[u8; KEY_LEN],
    input: &mut R,
    out: &mut W,
) -> Result<DecryptSummary> {
    let mut reader = HashingReader::new(input);

    let mut fixed = [0u8; 12];
    read_exact(&mut reader, &mut fixed, "容器头")?;
    if fixed[..4] != MAGIC {
        return Err(Error::Format("不是 OutGuard 容器（魔数不匹配）".into()));
    }
    let version = u16::from_le_bytes([fixed[4], fixed[5]]);
    if version != FORMAT_VERSION {
        return Err(Error::Format(format!(
            "不支持的容器版本：{version}（本程序支持 {FORMAT_VERSION}）"
        )));
    }
    let flags = u16::from_le_bytes([fixed[6], fixed[7]]);
    if flags != 0 {
        return Err(Error::Format(format!("容器标志位非法：0x{flags:04x}")));
    }
    let header_len = u32::from_le_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(Error::Format(format!("头部长度非法：{header_len}")));
    }

    let mut header_json = vec![0u8; header_len as usize];
    read_exact(&mut reader, &mut header_json, "头部 JSON")?;
    let header: Header = serde_json::from_slice(&header_json)
        .map_err(|e| Error::Format(format!("头部 JSON 解析失败：{e}")))?;
    let header_hash = crypto::sha256(&header_json);

    let mut len_buf = [0u8; 4];
    read_exact(&mut reader, &mut len_buf, "KeyBlock 长度")?;
    let key_block_len = u32::from_le_bytes(len_buf);
    let expected_key_block = (crypto::GCM_NONCE_LEN + KEY_LEN + GCM_TAG_LEN) as u32;
    if key_block_len != expected_key_block {
        return Err(Error::Format(format!(
            "KeyBlock 长度非法：{key_block_len}（期望 {expected_key_block}）"
        )));
    }
    let mut key_block = vec![0u8; key_block_len as usize];
    read_exact(&mut reader, &mut key_block, "KeyBlock")?;
    let dek = crypto::unwrap_key(kek, &key_block, &header_hash)?;

    read_exact(&mut reader, &mut len_buf, "分块大小")?;
    let chunk_size = u32::from_le_bytes(len_buf);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(Error::Format(format!("分块大小非法：{chunk_size}")));
    }
    let mut nonce_prefix = [0u8; 8];
    read_exact(&mut reader, &mut nonce_prefix, "nonce 前缀")?;

    let max_cipher_chunk = chunk_size + GCM_TAG_LEN as u32;
    let mut plain_size: u64 = 0;
    let mut index: u64 = 0;

    loop {
        read_exact(&mut reader, &mut len_buf, "分块长度")?;
        let cipher_len = u32::from_le_bytes(len_buf);
        if cipher_len == 0 {
            break; // END
        }
        if cipher_len < GCM_TAG_LEN as u32 || cipher_len > max_cipher_chunk {
            return Err(Error::Format(format!("分块长度非法：{cipher_len}")));
        }

        let mut ciphertext = vec![0u8; cipher_len as usize];
        read_exact(&mut reader, &mut ciphertext, "分块密文")?;
        let nonce = crypto::chunk_nonce(&nonce_prefix, index);
        let plain = crypto::decrypt_chunk(&dek, &nonce, &ciphertext, &header_hash)?;
        out.write_all(&plain)?;
        plain_size += plain.len() as u64;
        index += 1;
    }

    let computed: [u8; 32] = reader.digest();
    reader.stop_hashing();
    let mut footer = [0u8; FOOTER_LEN];
    read_exact(&mut reader, &mut footer, "尾部摘要")?;

    if computed != footer {
        return Err(Error::Format(
            "容器完整性校验失败（文件被截断或篡改）".into(),
        ));
    }

    out.flush()?;
    Ok(DecryptSummary {
        header,
        plain_size,
        cipher_sha256: computed,
    })
}

/// 循环读满缓冲区；返回实际读到的字节数（0 = EOF）。
fn read_full<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(filled)
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8], what: &str) -> Result<()> {
    reader
        .read_exact(buffer)
        .map_err(|e| Error::Format(format!("读取{what}失败（文件被截断？）：{e}")))
}

/// 写的同时累积 SHA-256。
struct HashingWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: Sha256,
}

impl<'a, W: Write> HashingWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn digest(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// 读的同时累积 SHA-256（读尾部摘要前停止累积）。
struct HashingReader<'a, R: Read> {
    inner: &'a mut R,
    hasher: Sha256,
    hashing: bool,
}

impl<'a, R: Read> HashingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            hashing: true,
        }
    }

    fn digest(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }

    fn stop_hashing(&mut self) {
        self.hashing = false;
    }
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        if self.hashing && read > 0 {
            self.hasher.update(&buf[..read]);
        }
        Ok(read)
    }
}

/// 校验一个容器文件能否被**完整**还原：头部、密钥块、每个分块的 GCM、尾部 SHA-256 全部通过。
///
/// 写入方（客户端加密、安全区落盘、导入）必须在删除原文件/降级占位符**之前**调用，
/// 否则一旦磁盘写坏就是不可逆的数据丢失。返回明文大小。
pub fn verify_file(path: &std::path::Path, kek: &[u8; KEY_LEN]) -> Result<u64> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path)
            .map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("打开待校验容器失败：{e}"))))?,
    );
    let mut sink = std::io::sink();
    let summary = decrypt_stream(kek, &mut reader, &mut sink)?;
    Ok(summary.plain_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_header() -> Header {
        Header {
            company: "示例科技有限公司".into(),
            notice: "本文件已加密，仅限安装 OutGuard 客户端的授权电脑打开。".into(),
            classification: "内部".into(),
            policy_id: "policy-1".into(),
            policy_version: 3,
            rule_id: "rule-docx".into(),
            creator: "zhangsan".into(),
            client_id: "client-abc".into(),
            created_at: "2026-10-26T10:00:00+08:00".into(),
            original_name: "合同.docx".into(),
            original_size: 0,
            plain_sha256: None,
        }
    }

    fn kek() -> [u8; KEY_LEN] {
        crypto::derive_policy_key(&[9u8; KEY_LEN], "policy-1", 1).expect("派生成功")
    }

    fn roundtrip(plain: &[u8], chunk_size: u32) -> DecryptSummary {
        let header = test_header();
        let mut input = Cursor::new(plain.to_vec());
        let mut container = Vec::new();
        let summary = encrypt_stream_with_chunk(&kek(), &header, chunk_size, &mut input, &mut container)
            .expect("加密成功");
        assert_eq!(summary.plain_size, plain.len() as u64);

        let mut reader = Cursor::new(container);
        let mut output = Vec::new();
        let result = decrypt_stream(&kek(), &mut reader, &mut output).expect("解密成功");
        assert_eq!(output, plain, "明文必须一致");
        assert_eq!(result.header, header);
        assert_eq!(result.plain_size, plain.len() as u64);
        result
    }

    #[test]
    fn empty_file_roundtrip() {
        let summary = roundtrip(b"", DEFAULT_CHUNK_SIZE);
        assert_eq!(summary.plain_size, 0);
    }

    #[test]
    fn small_file_roundtrip() {
        roundtrip(b"hello outguard", DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn multi_chunk_roundtrip() {
        let data = vec![0x5Au8; 4096 + 7];
        let summary = roundtrip(&data, 1024);
        assert_eq!(summary.plain_size, data.len() as u64);
    }

    #[test]
    fn header_is_readable_without_key() {
        let mut input = Cursor::new(b"plain".to_vec());
        let mut container = Vec::new();
        encrypt_stream(&kek(), &test_header(), &mut input, &mut container).expect("加密成功");

        // 未装客户端没有策略密钥，但能读到明文头（公司提示语）。
        let header = read_header(&mut Cursor::new(container)).expect("读头成功");
        assert_eq!(header.company, "示例科技有限公司");
        assert!(header.notice.contains("已加密"));
    }

    #[test]
    fn magic_detection() {
        assert!(is_container_magic(b"OGD1rest"));
        assert!(!is_container_magic(b"PK\x03\x04"));
        assert!(!is_container_magic(b"OGD"));
    }

    #[test]
    fn wrong_key_fails() {
        let mut input = Cursor::new(b"data".to_vec());
        let mut container = Vec::new();
        encrypt_stream(&kek(), &test_header(), &mut input, &mut container).expect("加密成功");

        let other = crypto::derive_policy_key(&[8u8; KEY_LEN], "policy-1", 1).expect("派生成功");
        let mut output = Vec::new();
        let err = decrypt_stream(&other, &mut Cursor::new(container), &mut output);
        assert!(err.is_err(), "换策略密钥必须解密失败");
    }

    #[test]
    fn header_tamper_fails() {
        let mut input = Cursor::new(b"data".to_vec());
        let mut container = Vec::new();
        encrypt_stream(&kek(), &test_header(), &mut input, &mut container).expect("加密成功");

        // 篡改头部里的公司名（等长替换，不破坏长度字段）。
        let marker = "示例科技有限公司".as_bytes();
        let pos = container
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("找到公司名");
        for byte in &mut container[pos..pos + marker.len()] {
            *byte = b'X';
        }

        let mut output = Vec::new();
        assert!(
            decrypt_stream(&kek(), &mut Cursor::new(container), &mut output).is_err(),
            "头部被篡改必须失败（AAD 绑定）"
        );
    }

    #[test]
    fn ciphertext_tamper_fails() {
        let mut input = Cursor::new(vec![1u8; 2048]);
        let mut container = Vec::new();
        encrypt_stream(&kek(), &test_header(), &mut input, &mut container).expect("加密成功");

        let last = container.len() - FOOTER_LEN - 1;
        container[last] ^= 0xFF;

        let mut output = Vec::new();
        assert!(decrypt_stream(&kek(), &mut Cursor::new(container), &mut output).is_err());
    }

    #[test]
    fn truncated_file_fails() {
        let mut input = Cursor::new(vec![2u8; 512]);
        let mut container = Vec::new();
        encrypt_stream(&kek(), &test_header(), &mut input, &mut container).expect("加密成功");

        let truncated = container[..container.len() - 8].to_vec();
        let mut output = Vec::new();
        assert!(decrypt_stream(&kek(), &mut Cursor::new(truncated), &mut output).is_err());
    }

    #[test]
    fn chunk_size_bounds_are_enforced() {
        let mut input = Cursor::new(b"x".to_vec());
        let mut out = Vec::new();
        assert!(encrypt_stream_with_chunk(&kek(), &test_header(), 0, &mut input, &mut out).is_err());

        let mut input = Cursor::new(b"x".to_vec());
        let mut out = Vec::new();
        assert!(
            encrypt_stream_with_chunk(&kek(), &test_header(), MAX_CHUNK_SIZE + 1, &mut input, &mut out)
                .is_err()
        );
    }

    #[test]
    fn safe_output_name_blocks_traversal() {
        let mut header = test_header();
        header.original_name = "../../etc/passwd".into();
        let name = safe_output_name(&header);
        assert!(!name.contains(".."), "必须清理路径穿越：{name}");
        assert!(!name.contains('/'));
    }
}
