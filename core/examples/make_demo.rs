//! 生成演示用加密容器（用于验证"未装客户端只能看到公司提示、装了客户端能识别归属"）。
//!
//! 用法：
//! ```powershell
//! cargo run -q -p pek-outguard-core --example make_demo -- target\demo.ogd
//! cargo run -q -p pek-outguard-server -- -preview target\demo.ogd
//! cargo run -q -p pek-outguard-client -- open target\demo.ogd
//! ```

use std::io::Cursor;

use pek_outguard_core::{container, crypto};

fn main() {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/demo.ogd".to_string());

    // 演示主密钥（正式环境由 Server 首次启动生成并落盘 Data/master.key）
    let master = [0x42u8; crypto::KEY_LEN];
    let kek = crypto::derive_policy_key(&master, "policy-rd", 1).expect("派生策略密钥");

    let plain = "这是一份演示用的机密文档内容。\n本文件在磁盘上始终是 AES-256-GCM 密文。\n";
    let header = container::Header {
        company: "示例科技有限公司".into(),
        notice: "本文件已加密，仅限安装 OutGuard 客户端的授权电脑打开。如需外发请联系信息安全部门（security@example.com）。"
            .into(),
        classification: "内部".into(),
        policy_id: "policy-rd".into(),
        policy_version: 3,
        rule_id: "rule-docx".into(),
        creator: "zhangsan".into(),
        client_id: "client-demo-01".into(),
        created_at: "2026-10-26T10:00:00+08:00".into(),
        original_name: "合同.docx".into(),
        original_size: plain.len() as u64,
        plain_sha256: None,
    };

    if let Some(parent) = std::path::Path::new(&output).parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut input = Cursor::new(plain.as_bytes());
    let mut file = std::fs::File::create(&output).expect("创建输出文件");
    let summary = container::encrypt_stream(&kek, &header, &mut input, &mut file).expect("加密成功");

    println!("已生成：{output}");
    println!("明文大小：{} 字节", summary.plain_size);
    println!("分块数量：{}", summary.chunk_count);
    println!("容器摘要：{}", crypto::hex(&summary.cipher_sha256));
}
