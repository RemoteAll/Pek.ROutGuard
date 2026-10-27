//! XTS 吞吐量基准与性能守门（手动运行，不进常规回归）。
//!
//! ```text
//! cargo test -p pek-outguard-core --release --test xts_perf -- --ignored --nocapture
//! ```
//!
//! # 为什么必须量这个
//!
//! 透明加密的每一次文件读写都要过一遍加解密。如果吞吐只有几百 MB/s，
//! 打开一个 200MB 的图纸/PPT 就要多花 0.5 秒，用户立刻能感觉到卡——这直接违反
//! 「不能让用户感知、不能影响实际使用性能」的要求。
//!
//! # 实测结论（本机，2026-10-27）
//!
//! | 实现 | 加密 | 解密 |
//! |---|---|---|
//! | 逐块串行（每块单独调 `encrypt_block`） | 388 MiB/s | 390 MiB/s |
//! | **8 路批量（现实现）** | **2261 MiB/s** | **2099 MiB/s** |
//!
//! 加速 5.7×。典型文件耗时：1MB→0.4ms、20MB→8.8ms、100MB→44ms、500MB→221ms。
//! 结论：**普通办公文件加解密在 10ms 内，用户完全无感，这条技术路线可以上**。
//!
//! # 本文件的两项职责
//!
//! 1. **对拍**：批量实现必须与"逐块逐次调用"的参考实现产出**逐字节相同**的密文
//!    ——优化只能改快慢，绝不能改算法；
//! 2. **守门**：吞吐低于阈值就失败，防止将来某次改动把性能悄悄打回串行水平。

use std::time::Instant;

use aes::Aes256;
use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use pek_outguard_core::xts::{BLOCK_LEN, FileId, XtsCipher};

const FILE_ID: FileId = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// 吞吐下限（MiB/s）。实测约 2100，留足余量：远低于此说明优化被回退或误改。
const MIN_THROUGHPUT: f64 = 500.0;

fn key_material() -> Vec<u8> {
    (0u8..64).collect()
}

fn throughput(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

/// **参考实现**：逐块 `encrypt_block`，与 `xts.rs` 的批量版等价但慢。
///
/// 它在这里的作用是"算法定义的可读版本"——如果批量版改了密文，对拍立刻失败。
struct SerialXts {
    key1: Aes256,
    key2: Aes256,
}

impl SerialXts {
    fn new(key: &[u8]) -> Self {
        Self {
            key1: Aes256::new_from_slice(&key[..32]).expect("key1"),
            key2: Aes256::new_from_slice(&key[32..]).expect("key2"),
        }
    }

    fn encrypt(&self, file_id: &FileId, offset: u64, data: &mut [u8]) {
        let base = offset / BLOCK_LEN as u64;
        let (blocks, _) = data.as_chunks_mut::<BLOCK_LEN>();
        for (i, chunk) in blocks.iter_mut().enumerate() {
            // tweak = AES_ECB(key2, file_id || block_index)
            let mut input = [0u8; BLOCK_LEN];
            input[..8].copy_from_slice(file_id);
            input[8..].copy_from_slice(&(base + i as u64).to_be_bytes());
            let mut tweak = GenericArray::<u8, U16>::clone_from_slice(&input);
            self.key2.encrypt_block(&mut tweak);

            // C = AES_ECB(key1, P xor T) xor T
            let mut block = GenericArray::<u8, U16>::clone_from_slice(chunk);
            for j in 0..BLOCK_LEN {
                block[j] ^= tweak[j];
            }
            self.key1.encrypt_block(&mut block);
            for j in 0..BLOCK_LEN {
                chunk[j] = block[j] ^ tweak[j];
            }
        }
    }
}

#[test]
#[ignore = "性能基准，手动运行"]
fn xts_throughput() {
    // 64 MiB：足够摊掉启动抖动，也接近"大文件"的典型规模
    const TOTAL: usize = 64 * 1024 * 1024;
    const ROUNDS: usize = 5;

    let key = key_material();
    let cipher = XtsCipher::new(&key).expect("建 cipher");

    let mut buffer = vec![0u8; TOTAL];
    for (i, b) in buffer.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let plain = buffer.clone();

    println!(
        "\n=== XTS 吞吐量基准（{} MiB × {ROUNDS} 轮，取最快）===",
        TOTAL / 1024 / 1024
    );

    // 现实现（8 路批量）
    let mut best_enc = f64::MAX;
    for _ in 0..ROUNDS {
        let start = Instant::now();
        cipher.encrypt_range(&FILE_ID, 0, &mut buffer).expect("加密");
        best_enc = best_enc.min(start.elapsed().as_secs_f64());
    }
    let mut best_dec = f64::MAX;
    for _ in 0..ROUNDS {
        let start = Instant::now();
        cipher
            .decrypt_range(&FILE_ID, 0, &mut buffer)
            .expect("解密");
        best_dec = best_dec.min(start.elapsed().as_secs_f64());
    }
    let enc_rate = throughput(TOTAL, best_enc);
    let dec_rate = throughput(TOTAL, best_dec);
    println!("现实现  加密：{enc_rate:>15.1} MiB/s（{best_enc:.4} 秒）");
    println!("现实现  解密：{dec_rate:>15.1} MiB/s（{best_dec:.4} 秒）");

    // 参考实现（逐块串行），只用来对拍快照与给出对照数字
    let serial = SerialXts::new(&key);
    let mut reference = plain.clone();
    let start = Instant::now();
    serial.encrypt(&FILE_ID, 0, &mut reference);
    let serial_secs = start.elapsed().as_secs_f64();
    println!(
        "参考(逐块) 加密：{:>15.1} MiB/s（{serial_secs:.4} 秒）",
        throughput(TOTAL, serial_secs)
    );
    println!("批量相对加速：{:.1}×", serial_secs / best_enc);

    // ① 对拍：批量实现必须与逐块参考实现产出逐字节相同的密文
    let mut batch_ct = plain.clone();
    cipher
        .encrypt_range(&FILE_ID, 0, &mut batch_ct)
        .expect("加密");
    assert_eq!(
        batch_ct, reference,
        "批量版密文与逐块参考实现不一致——优化改了算法，必须回退"
    );
    println!("对拍：批量版密文与逐块参考实现逐字节一致 ✓");

    // ② 往返
    let mut roundtrip = batch_ct.clone();
    cipher
        .decrypt_range(&FILE_ID, 0, &mut roundtrip)
        .expect("解密");
    assert_eq!(roundtrip, plain, "解密必须还原原文");
    println!("往返：解回原文逐字节一致 ✓");

    // ③ 非 8 倍数的尾部批次也要正确（BATCH 不整除时走短批）
    let odd_plain = plain[..BLOCK_LEN * 13].to_vec();
    let mut odd_ct = odd_plain.clone();
    cipher
        .encrypt_range(&FILE_ID, 0, &mut odd_ct)
        .expect("加密");
    let mut odd_ref = odd_plain.clone();
    serial.encrypt(&FILE_ID, 0, &mut odd_ref);
    assert_eq!(
        odd_ct, odd_ref,
        "13 块（非 8 倍数）批次必须与参考实现一致"
    );
    cipher
        .decrypt_range(&FILE_ID, 0, &mut odd_ct)
        .expect("解密");
    assert_eq!(odd_ct, odd_plain, "13 块往返必须还原");
    println!("短批：13 块（非 8 倍数）对拍与往返均通过 ✓");

    // ④ 守门：吞吐不能掉回串行水平
    assert!(
        enc_rate >= MIN_THROUGHPUT && dec_rate >= MIN_THROUGHPUT,
        "吞吐跌破守门线 {MIN_THROUGHPUT} MiB/s（加密 {enc_rate:.1}、解密 {dec_rate:.1}）——检查是否误改了批量实现"
    );

    // 用户真正感受到的数字
    println!("\n--- 典型文件加解密耗时（按实测 {enc_rate:.0} MiB/s）---");
    for size_mb in [1usize, 5, 20, 100, 500] {
        let secs = size_mb as f64 / enc_rate;
        println!("  {size_mb:>3} MB → {:.1} ms", secs * 1000.0);
    }
    println!();
}
