//! 服务端端到端（数据层 + 策略组装）：
//! 注册 → 心跳 → 拉策略（客户端令牌解包策略密钥）→ 上报事件（幂等去重）。

use base64::Engine as _;
use pek_outguard_core::crypto;
use pek_outguard_core::protocol::{
    ClientEvent, EventType, HardwareInfo, HeartbeatRequest, RegisterRequest,
};
use pek_outguard_server::app::App;
use pek_outguard_server::client_api::build_policy_bundle;
use pek_outguard_server::db;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "outguard-server-{}-{stamp}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    dir
}

fn register_request() -> RegisterRequest {
    RegisterRequest {
        machine_id: "0123456789abcdef0123456789abcdef".into(),
        hostname: "PC-TEST-01".into(),
        os: "Windows 11 23H2 x64".into(),
        client_version: "0.1.0".into(),
        public_key: "AAAA".into(),
        enroll_code: String::new(),
        hardware: Some(HardwareInfo {
            cpu: "Intel Core i7-13700".into(),
            memory_mb: 32768,
            disk_total_gb: 1024,
            os_build: "22631.4317".into(),
            domain: "CORP".into(),
        }),
        logged_user: "zhangsan".into(),
        ip: "10.0.0.8".into(),
        mac: "00-11-22-33-44-55".into(),
        installed_at: 1_800_000_000,
        account: String::new(),
        password: String::new(),
    }
}

#[test]
fn register_heartbeat_policy_events_flow() {
    let dir = temp_dir("flow");
    let app = App::open(&dir).expect("打开服务端");

    let token = "00112233445566778899aabbccddeeff";

    // ① 注册（首次）
    assert!(
        db::find_by_machine(&app.store, "0123456789abcdef0123456789abcdef")
            .expect("查询")
            .is_none()
    );
    let token_hash = crypto::hex(&crypto::sha256(token.as_bytes()));
    db::upsert_registration(&app.store, &register_request(), "c-1", &token_hash, "active")
        .expect("注册成功");

    let record = db::find_by_client_id(&app.store, "c-1")
        .expect("查询")
        .expect("终端存在");
    assert_eq!(record.status, "active");
    assert_eq!(record.token_hash, token_hash);

    // ② 心跳（只发变化项：hostname 变化，其余 None）
    let heartbeat = HeartbeatRequest {
        client_id: "c-1".into(),
        client_version: "0.1.0".into(),
        policy_version: 0,
        hostname: Some("PC-TEST-01-RENAMED".into()),
        logged_user: None,
        os: None,
        health: None,
        anomalies: None,
        ip: Some("10.0.0.9".into()),
        mac: None,
        hardware: None,
    };
    db::apply_heartbeat(&app.store, &record, &heartbeat, db::now()).expect("心跳成功");

    // ③ 拉策略：内置默认规则集 + 用客户端令牌可解包的策略密钥
    let bundle = build_policy_bundle(&app, token).expect("策略包");
    assert_eq!(bundle.policy_sets.len(), 1, "未配置时下发内置默认规则集");
    assert_eq!(bundle.policy_sets[0].id, "default");
    assert_eq!(bundle.wrapped_keys.len(), 1);
    assert!(
        bundle
            .exclude_paths
            .iter()
            .any(|path| path.contains("OutGuard")),
        "必须带受控临时目录排除项"
    );

    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(&bundle.wrapped_keys[0].wrapped_key)
        .expect("base64 解码");
    let policy_key = crypto::unwrap_for_client(token, &wrapped).expect("客户端解包策略密钥");
    let expected = crypto::derive_policy_key(&app.master, "default", 1).expect("派生");
    assert_eq!(policy_key, expected, "下发密钥必须与服务端派生一致");

    // 换一个令牌解包必须失败（令牌是密钥保护的一部分）
    assert!(crypto::unwrap_for_client("ffffffffffffffffffffffffffffffff", &wrapped).is_err());

    // ④ 上报事件（同一 EventId 重传必须幂等）
    let event = ClientEvent {
        event_id: "evt-0001".into(),
        event_type: EventType::Encrypt,
        occurred_at: 1_800_000_100_000,
        path: Some("D:\\Work\\合同.docx".into()),
        rule_id: Some("office-pdf-cad".into()),
        user: Some("zhangsan".into()),
        process_name: Some("WINWORD.EXE".into()),
        size: Some(2048),
        detail: None,
    };
    let (accepted, duplicated) =
        db::insert_events(&app.store, "c-1", std::slice::from_ref(&event)).expect("写入事件");
    assert_eq!((accepted, duplicated), (1, 0));
    let (accepted, duplicated) =
        db::insert_events(&app.store, "c-1", std::slice::from_ref(&event)).expect("重传事件");
    assert_eq!((accepted, duplicated), (0, 1), "重传必须去重");
    assert_eq!(db::event_count(&app.store).expect("统计"), 1);

    // ⑤ 保存规则集：首次启动已落库默认规则集 v1；改规则 → v2；无变化不升
    let mut policy = bundle.policy_sets[0].clone();
    assert_eq!(policy.id, "default");
    assert_eq!(policy.version, 1, "首次启动落库为 v1");
    policy.rules[0].extensions.push("txt".into());
    let version = db::save_policy(&app.store, &policy, true, "测试").expect("保存规则集");
    assert_eq!(version, 2, "规则变化必须升版本");
    let version = db::save_policy(&app.store, &policy, true, "测试").expect("再次保存");
    assert_eq!(version, 2, "无变化不升版本");
    policy.rules[0].extensions.push("csv".into());
    let version = db::save_policy(&app.store, &policy, true, "测试").expect("改动后保存");
    assert_eq!(version, 3, "再次变化继续升版本");

    // ⑥ 准入状态切换
    assert!(
        db::set_client_status(&app.store, "c-1", "disabled").expect("改状态"),
        "终端存在"
    );
    let record = db::find_by_client_id(&app.store, "c-1")
        .expect("查询")
        .expect("终端存在");
    assert_eq!(record.status, "disabled");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn client_stats_counts_online_and_pending() {
    let dir = temp_dir("stats");
    let app = App::open(&dir).expect("打开服务端");

    let hash = crypto::hex(&crypto::sha256(b"token-a"));
    let mut first = register_request();
    first.machine_id = "aaaa".into();
    db::upsert_registration(&app.store, &first, "c-a", &hash, "active").expect("注册 A");

    let mut second = register_request();
    second.machine_id = "bbbb".into();
    second.hostname = "PC-TEST-02".into();
    db::upsert_registration(&app.store, &second, "c-b", &hash, "pending").expect("注册 B");

    let (total, online, pending) = db::client_stats(&app.store).expect("统计");
    assert_eq!(total, 2);
    assert_eq!(pending, 1);
    assert!(online >= 1, "刚注册的终端应计入在线（LastSeen 刚写入）");

    let list = db::list_clients(&app.store, 10).expect("列表");
    assert_eq!(list.len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}
