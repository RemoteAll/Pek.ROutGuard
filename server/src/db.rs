//! 数据层：终端台账 / 规则集 / 审计事件。
//!
//! 设计口径（对齐 `Pek.RCode/docs/使用规范.md`）：
//! - 高频外部写入（心跳、事件）用**表级 API**，不用实体脏更新；
//! - 事件表 `InsertOnly`，按 `EventId` 去重（客户端重传幂等）；
//! - 长文本列用 `Text`（MySQL `LONGTEXT`，避免行宽越界）；
//! - 终端表 `MaxCacheCount=0`（写频繁，不开整表缓存）。

use std::path::Path;
use std::sync::Arc;

use chrono::{NaiveDateTime, Utc};
use pek_outguard_core::protocol::{ClientEvent, HeartbeatRequest, RegisterRequest};
use pek_outguard_core::rules::PolicySet;
use pek_rcode::dal::TableRef;
use pek_rcode::query::{Query, Where};
use pek_rcode::session::DbRow;
use pek_rcode::store::{self, SharedStore};
use pek_rcode::value::DbValue;
use pek_rcode::{Dal, EntityModel};
use serde_json::{Value, json};

/// 内嵌 XCode 模型（唯一事实来源）。
const MODEL_XML: &str = include_str!("../Entity/Model.xml");
/// 数据库文件（相对程序基目录）。
pub const DB_RELATIVE: &str = "Data/outguard.db";

/// 打开（或首次创建）数据库共享存储。
pub fn open(base: &Path) -> Result<Arc<SharedStore>, String> {
    store::get_or_open(base, || open_dal(base)).map(|(shared, _)| shared)
}

fn open_dal(base: &Path) -> Result<Dal, String> {
    let model = EntityModel::parse(MODEL_XML).map_err(|e| format!("Model.xml 解析失败：{e}"))?;
    let db_path = base.join(DB_RELATIVE);
    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
    }
    let conn = format!(
        "Data Source={};Provider=SQLite;ShowSql=false",
        db_path.display()
    );
    let dal = Dal::open_with_model(&conn, model).map_err(|e| format!("打开数据库失败：{e}"))?;
    dal.sync_schema().map_err(|e| format!("同步表结构失败：{e}"))?;
    dhrust::info!("OutGuard 数据库就绪（{}）", db_path.display());
    Ok(dal)
}

/// 当前时间（UTC，数据库 DateTime 列统一存 UTC）。
pub fn now() -> NaiveDateTime {
    Utc::now().naive_utc()
}

fn table<'a>(dal: &'a Dal, name: &str) -> Result<TableRef<'a>, String> {
    dal.table(name).map_err(|e| format!("表 {name} 不可用：{e}"))
}

fn db_text(value: Option<&DbValue>) -> String {
    match value {
        Some(DbValue::Text(text)) => text.clone(),
        Some(DbValue::Int(number)) => number.to_string(),
        Some(DbValue::Bool(flag)) => flag.to_string(),
        Some(DbValue::DateTime(time)) => time.format("%Y-%m-%d %H:%M:%S").to_string(),
        Some(DbValue::Null) | None => String::new(),
        Some(other) => format!("{other:?}"),
    }
}

fn db_int(value: Option<&DbValue>) -> i64 {
    match value {
        Some(DbValue::Int(number)) => *number,
        Some(DbValue::Bool(flag)) => i64::from(*flag),
        Some(DbValue::Text(text)) => text.parse().unwrap_or(0),
        _ => 0,
    }
}

fn db_datetime(value: Option<&DbValue>) -> Option<NaiveDateTime> {
    match value {
        Some(DbValue::DateTime(time)) => Some(*time),
        Some(DbValue::Text(text)) => {
            NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S").ok()
        }
        _ => None,
    }
}

fn dt(value: NaiveDateTime) -> DbValue {
    DbValue::DateTime(value)
}

// ————— 终端 —————

/// 终端记录（内部用）。
#[derive(Debug, Clone)]
pub struct ClientRecord {
    /// 自增主键
    pub id: i64,
    /// 终端 ID
    pub client_id: String,
    /// 设备唯一码
    pub machine_id: String,
    /// 主机名
    pub host: String,
    /// 状态
    pub status: String,
    /// 已生效策略版本
    pub policy_version: i32,
    /// 令牌哈希
    pub token_hash: String,
    /// 最后心跳
    pub last_seen: Option<NaiveDateTime>,
}

fn client_from_row(row: &DbRow) -> ClientRecord {
    ClientRecord {
        id: db_int(row.get_by_name("Id")),
        client_id: db_text(row.get_by_name("ClientId")),
        machine_id: db_text(row.get_by_name("MachineId")),
        host: db_text(row.get_by_name("Host")),
        status: db_text(row.get_by_name("Status")),
        policy_version: db_int(row.get_by_name("PolicyVersion")) as i32,
        token_hash: db_text(row.get_by_name("TokenHash")),
        last_seen: db_datetime(row.get_by_name("LastSeen")),
    }
}

fn query_one(
    store: &SharedStore,
    table_name: &str,
    filter: Where,
) -> Result<Option<DbRow>, String> {
    let dal = store.dal();
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    let query = Query::new().filter(filter).take(1);
    let set = table(dal, table_name)?
        .query(session.as_mut(), &query)
        .map_err(|e| format!("查询失败：{e}"))?;
    Ok(set.rows.into_iter().next())
}

/// 按机器码查找终端。
pub fn find_by_machine(store: &SharedStore, machine_id: &str) -> Result<Option<ClientRecord>, String> {
    let filter = Where::new().eq("MachineId", DbValue::Text(machine_id.to_string()));
    Ok(query_one(store, "OgClient", filter)?.map(|row| client_from_row(&row)))
}

/// 按终端 ID 查找。
pub fn find_by_client_id(store: &SharedStore, client_id: &str) -> Result<Option<ClientRecord>, String> {
    let filter = Where::new().eq("ClientId", DbValue::Text(client_id.to_string()));
    Ok(query_one(store, "OgClient", filter)?.map(|row| client_from_row(&row)))
}

/// 注册（已存在则更新资产信息，保留原状态与令牌）。
pub fn upsert_registration(
    store: &SharedStore,
    request: &RegisterRequest,
    client_id: &str,
    token_hash: &str,
    status: &str,
) -> Result<(), String> {
    let dal = store.dal();
    let hardware = request.hardware.clone().unwrap_or_default();
    let now = now();

    if let Some(existing) = find_by_machine(store, &request.machine_id)? {
        let sets: Vec<(&str, DbValue)> = vec![
            ("Host", DbValue::Text(request.hostname.clone())),
            ("Os", DbValue::Text(request.os.clone())),
            ("OsBuild", DbValue::Text(hardware.os_build)),
            ("Cpu", DbValue::Text(hardware.cpu)),
            ("MemoryMb", DbValue::Int(hardware.memory_mb as i64)),
            ("DiskTotalGb", DbValue::Int(hardware.disk_total_gb as i64)),
            ("Domain", DbValue::Text(hardware.domain)),
            ("Ip", DbValue::Text(request.ip.clone())),
            ("Mac", DbValue::Text(request.mac.clone())),
            ("LoggedUser", DbValue::Text(request.logged_user.clone())),
            ("ClientVersion", DbValue::Text(request.client_version.clone())),
            ("PubKey", DbValue::Text(request.public_key.clone())),
            // 重装/重注册换发令牌：哈希同步更新，旧令牌立即失效。
            ("TokenHash", DbValue::Text(token_hash.to_string())),
            ("LastSeen", dt(now)),
            ("UpdateTime", dt(now)),
        ];
        let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
        table(dal, "OgClient")?
            .update_by_pk(session.as_mut(), &sets, &[DbValue::Int(existing.id)])
            .map_err(|e| format!("更新终端失败：{e}"))?;
        return Ok(());
    }

    let fields: Vec<(&str, DbValue)> = vec![
        ("ClientId", DbValue::Text(client_id.to_string())),
        ("MachineId", DbValue::Text(request.machine_id.clone())),
        ("Host", DbValue::Text(request.hostname.clone())),
        ("Os", DbValue::Text(request.os.clone())),
        ("OsBuild", DbValue::Text(hardware.os_build)),
        ("Cpu", DbValue::Text(hardware.cpu)),
        ("MemoryMb", DbValue::Int(hardware.memory_mb as i64)),
        ("DiskTotalGb", DbValue::Int(hardware.disk_total_gb as i64)),
        ("Domain", DbValue::Text(hardware.domain)),
        ("Ip", DbValue::Text(request.ip.clone())),
        ("Mac", DbValue::Text(request.mac.clone())),
        ("LoggedUser", DbValue::Text(request.logged_user.clone())),
        ("ClientVersion", DbValue::Text(request.client_version.clone())),
        ("PolicyVersion", DbValue::Int(0)),
        ("Status", DbValue::Text(status.to_string())),
        ("DeptId", DbValue::Int(0)),
        ("PubKey", DbValue::Text(request.public_key.clone())),
        ("TokenHash", DbValue::Text(token_hash.to_string())),
        ("InstalledAt", DbValue::Int(request.installed_at)),
        ("LastSeen", dt(now)),
        ("CreateTime", dt(now)),
        ("UpdateTime", dt(now)),
    ];
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    table(dal, "OgClient")?
        .insert(session.as_mut(), &fields)
        .map_err(|e| format!("写入终端失败：{e}"))?;
    Ok(())
}

/// 心跳：只更新变化项（`None` 的字段保留旧值），并推进 `LastSeen`。
pub fn apply_heartbeat(
    store: &SharedStore,
    record: &ClientRecord,
    request: &HeartbeatRequest,
    now: NaiveDateTime,
) -> Result<(), String> {
    let dal = store.dal();
    let mut sets: Vec<(&str, DbValue)> = vec![
        ("LastSeen", dt(now)),
        ("UpdateTime", dt(now)),
        (
            "ClientVersion",
            DbValue::Text(request.client_version.clone()),
        ),
        ("PolicyVersion", DbValue::Int(i64::from(request.policy_version))),
    ];
    if let Some(host) = &request.hostname {
        sets.push(("Host", DbValue::Text(host.clone())));
    }
    if let Some(user) = &request.logged_user {
        sets.push(("LoggedUser", DbValue::Text(user.clone())));
    }
    if let Some(os) = &request.os {
        sets.push(("Os", DbValue::Text(os.clone())));
    }
    if let Some(ip) = &request.ip {
        sets.push(("Ip", DbValue::Text(ip.clone())));
    }
    if let Some(mac) = &request.mac {
        sets.push(("Mac", DbValue::Text(mac.clone())));
    }
    if let Some(hardware) = &request.hardware {
        sets.push(("Cpu", DbValue::Text(hardware.cpu.clone())));
        sets.push(("MemoryMb", DbValue::Int(hardware.memory_mb as i64)));
        sets.push(("DiskTotalGb", DbValue::Int(hardware.disk_total_gb as i64)));
        sets.push(("OsBuild", DbValue::Text(hardware.os_build.clone())));
        sets.push(("Domain", DbValue::Text(hardware.domain.clone())));
    }

    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    table(dal, "OgClient")?
        .update_by_pk(session.as_mut(), &sets, &[DbValue::Int(record.id)])
        .map_err(|e| format!("更新心跳失败：{e}"))?;
    Ok(())
}

/// 终端列表（面板视图；按创建时间倒序）。
pub fn list_clients(store: &SharedStore, limit: usize) -> Result<Vec<Value>, String> {
    let dal = store.dal();
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    let query = Query::new().take(limit);
    let set = table(dal, "OgClient")?
        .query(session.as_mut(), &query)
        .map_err(|e| format!("查询终端失败：{e}"))?;

    let mut rows: Vec<(i64, Value)> = set
        .rows
        .iter()
        .map(|row| {
            let id = db_int(row.get_by_name("Id"));
            (
                id,
                json!({
                    "clientId": db_text(row.get_by_name("ClientId")),
                    "machineId": db_text(row.get_by_name("MachineId")),
                    "host": db_text(row.get_by_name("Host")),
                    "os": db_text(row.get_by_name("Os")),
                    "cpu": db_text(row.get_by_name("Cpu")),
                    "memoryMb": db_int(row.get_by_name("MemoryMb")),
                    "diskTotalGb": db_int(row.get_by_name("DiskTotalGb")),
                    "domain": db_text(row.get_by_name("Domain")),
                    "ip": db_text(row.get_by_name("Ip")),
                    "mac": db_text(row.get_by_name("Mac")),
                    "loggedUser": db_text(row.get_by_name("LoggedUser")),
                    "clientVersion": db_text(row.get_by_name("ClientVersion")),
                    "policyVersion": db_int(row.get_by_name("PolicyVersion")),
                    "status": db_text(row.get_by_name("Status")),
                    "lastSeen": db_text(row.get_by_name("LastSeen")),
                }),
            )
        })
        .collect();
    rows.sort_by_key(|item| std::cmp::Reverse(item.0));
    Ok(rows.into_iter().map(|(_, value)| value).collect())
}

/// 设置终端准入状态（统一转大写无关的小写值）。
pub fn set_client_status(store: &SharedStore, client_id: &str, status: &str) -> Result<bool, String> {
    let Some(record) = find_by_client_id(store, client_id)? else {
        return Ok(false);
    };
    let dal = store.dal();
    let now = now();
    let sets: Vec<(&str, DbValue)> = vec![
        ("Status", DbValue::Text(status.to_string())),
        ("UpdateTime", dt(now)),
    ];
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    table(dal, "OgClient")?
        .update_by_pk(session.as_mut(), &sets, &[DbValue::Int(record.id)])
        .map_err(|e| format!("更新终端状态失败：{e}"))?;
    Ok(true)
}

/// 终端统计：总数 / 在线（5 分钟内有心跳）/ 待准入。
pub fn client_stats(store: &SharedStore) -> Result<(i64, i64, i64), String> {
    let dal = store.dal();
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    let table_ref = table(dal, "OgClient")?;
    let total = table_ref
        .count(session.as_mut(), None)
        .map_err(|e| format!("统计失败：{e}"))?;
    let pending = table_ref
        .count(
            session.as_mut(),
            Some(&Where::new().eq("Status", DbValue::Text("pending".into()))),
        )
        .map_err(|e| format!("统计失败：{e}"))?;
    let online_cutoff = now() - chrono::Duration::minutes(5);
    let online = table_ref
        .count(
            session.as_mut(),
            Some(&Where::new().ge("LastSeen", dt(online_cutoff))),
        )
        .map_err(|e| format!("统计失败：{e}"))?;
    Ok((total, online, pending))
}

// ————— 规则集 —————

/// 列出全部规则集（含禁用；解析规则 JSON）。
pub fn list_policies(store: &SharedStore) -> Result<Vec<(PolicySet, bool, String)>, String> {
    let dal = store.dal();
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    let query = Query::new().take(500);
    let set = table(dal, "OgPolicySet")?
        .query(session.as_mut(), &query)
        .map_err(|e| format!("查询规则集失败：{e}"))?;

    let mut out = Vec::new();
    for row in &set.rows {
        let policy_id = db_text(row.get_by_name("PolicyId"));
        let name = db_text(row.get_by_name("Name"));
        let version = db_int(row.get_by_name("Version")) as u32;
        let key_version = db_int(row.get_by_name("KeyVersion")) as u32;
        let default_action = db_text(row.get_by_name("DefaultAction"));
        let exclude: Vec<String> =
            serde_json::from_str(&db_text(row.get_by_name("ExcludePaths"))).unwrap_or_default();
        let rules = serde_json::from_str(&db_text(row.get_by_name("RulesJson"))).unwrap_or_default();
        // SQLite 布尔列读回可能是 Int(0/1)，统一按数值判定。
        let enabled = db_int(row.get_by_name("Enabled")) != 0;

        out.push((
            PolicySet {
                id: policy_id,
                name,
                version,
                key_version: key_version.max(1),
                default_action: parse_action(&default_action),
                exclude_paths: exclude,
                rules,
            },
            enabled,
            db_text(row.get_by_name("Remark")),
        ));
    }
    Ok(out)
}

fn parse_action(text: &str) -> pek_outguard_core::rules::Action {
    use pek_outguard_core::rules::Action;
    match text {
        "encrypt" => Action::Encrypt,
        "block_write" => Action::BlockWrite,
        "audit" => Action::Audit,
        _ => Action::Plaintext,
    }
}

/// 保存规则集（不存在则创建；规则有变化则版本自增）。
pub fn save_policy(
    store: &SharedStore,
    policy: &PolicySet,
    enabled: bool,
    remark: &str,
) -> Result<u32, String> {
    policy.validate().map_err(|e| e.to_string())?;
    let dal = store.dal();
    let now = now();
    let rules_json = serde_json::to_string(&policy.rules).map_err(|e| format!("规则序列化失败：{e}"))?;
    let exclude_json =
        serde_json::to_string(&policy.exclude_paths).map_err(|e| format!("排除项序列化失败：{e}"))?;

    let existing = {
        let filter = Where::new().eq("PolicyId", DbValue::Text(policy.id.clone()));
        query_one(store, "OgPolicySet", filter)?
    };

    // 版本规则：新建 = 1；规则/排除项/默认动作有变化 = 旧版本 + 1；无变化 = 保留。
    let mut version = 1u32;
    if let Some(row) = &existing {
        let old_version = db_int(row.get_by_name("Version")).max(0) as u32;
        let old_rules = db_text(row.get_by_name("RulesJson"));
        let old_exclude = db_text(row.get_by_name("ExcludePaths"));
        let old_default = db_text(row.get_by_name("DefaultAction"));
        let changed = old_rules != rules_json
            || old_exclude != exclude_json
            || old_default != policy.default_action.as_str();
        version = if changed {
            old_version + 1
        } else {
            old_version.max(1)
        };
    }

    let fields: Vec<(&str, DbValue)> = vec![
        ("PolicyId", DbValue::Text(policy.id.clone())),
        ("Name", DbValue::Text(policy.name.clone())),
        ("Version", DbValue::Int(i64::from(version))),
        ("KeyVersion", DbValue::Int(i64::from(policy.key_version.max(1)))),
        (
            "DefaultAction",
            DbValue::Text(policy.default_action.as_str().to_string()),
        ),
        ("ExcludePaths", DbValue::Text(exclude_json)),
        ("RulesJson", DbValue::Text(rules_json)),
        ("Enabled", DbValue::Bool(enabled)),
        ("Remark", DbValue::Text(remark.to_string())),
        ("UpdateTime", dt(now)),
    ];

    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    if let Some(row) = existing {
        let id = db_int(row.get_by_name("Id"));
        table(dal, "OgPolicySet")?
            .update_by_pk(session.as_mut(), &fields, &[DbValue::Int(id)])
            .map_err(|e| format!("更新规则集失败：{e}"))?;
    } else {
        let mut all = fields.clone();
        all.push(("CreateTime", dt(now)));
        table(dal, "OgPolicySet")?
            .insert(session.as_mut(), &all)
            .map_err(|e| format!("新增规则集失败：{e}"))?;
    }
    Ok(version)
}

/// 策略总版本（启用规则集的最大版本；无规则集时为 0）。
pub fn policy_bundle_version(store: &SharedStore) -> Result<u32, String> {
    let policies = list_policies(store)?;
    Ok(policies
        .iter()
        .filter(|(_, enabled, _)| *enabled)
        .map(|(policy, _, _)| policy.version)
        .max()
        .unwrap_or(0))
}

/// 首次启动落库内置默认规则集（保证面板可见、心跳与策略包版本一致）。
pub fn ensure_default_policy(store: &SharedStore) -> Result<(), String> {
    if !list_policies(store)?.is_empty() {
        return Ok(());
    }
    save_policy(
        store,
        &PolicySet::builtin_default(),
        true,
        "系统内置（首次启动生成）",
    )
    .map(|_| ())
}

// ————— 事件 —————

/// 批量写入审计事件（按 `EventId` 去重）；返回 `(accepted, duplicated)`。
pub fn insert_events(
    store: &SharedStore,
    client_id: &str,
    events: &[ClientEvent],
) -> Result<(usize, usize), String> {
    let dal = store.dal();
    let received = now();
    let mut accepted = 0usize;
    let mut duplicated = 0usize;
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;

    for event in events {
        let filter = Where::new().eq("EventId", DbValue::Text(event.event_id.clone()));
        if query_one(store, "OgClientEvent", filter)?.is_some() {
            duplicated += 1;
            continue;
        }
        let occurred = chrono::DateTime::from_timestamp_millis(event.occurred_at)
            .map(|value| value.naive_utc())
            .unwrap_or(received);

        let fields: Vec<(&str, DbValue)> = vec![
            ("EventId", DbValue::Text(event.event_id.clone())),
            ("ClientId", DbValue::Text(client_id.to_string())),
            (
                "EventType",
                DbValue::Text(event.event_type.as_str().to_string()),
            ),
            ("OccurredAt", dt(occurred)),
            ("ReceivedAt", dt(received)),
            ("Path", DbValue::Text(event.path.clone().unwrap_or_default())),
            ("RuleId", DbValue::Text(event.rule_id.clone().unwrap_or_default())),
            ("UserName", DbValue::Text(event.user.clone().unwrap_or_default())),
            (
                "ProcessName",
                DbValue::Text(event.process_name.clone().unwrap_or_default()),
            ),
            ("Size", DbValue::Int(event.size.unwrap_or(0) as i64)),
            ("Detail", DbValue::Text(event.detail.clone().unwrap_or_default())),
        ];
        table(dal, "OgClientEvent")?
            .insert(session.as_mut(), &fields)
            .map_err(|e| format!("写入事件失败：{e}"))?;
        accepted += 1;
    }
    Ok((accepted, duplicated))
}

// ————— 设置（键值）─────

/// 读取设置项（不存在返回 `None`）。
pub fn get_setting(store: &SharedStore, name: &str) -> Result<Option<String>, String> {
    let filter = Where::new().eq("Name", DbValue::Text(name.to_string()));
    Ok(query_one(store, "OgSetting", filter)?
        .map(|row| db_text(row.get_by_name("Value"))))
}

/// 写入设置项（存在则覆盖）。
pub fn set_setting(store: &SharedStore, name: &str, value: &str) -> Result<(), String> {
    let dal = store.dal();
    let now = now();
    let existing = query_one(
        store,
        "OgSetting",
        Where::new().eq("Name", DbValue::Text(name.to_string())),
    )?;
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    if let Some(row) = existing {
        let id = db_int(row.get_by_name("Id"));
        let fields: Vec<(&str, DbValue)> = vec![
            ("Value", DbValue::Text(value.to_string())),
            ("UpdateTime", dt(now)),
        ];
        table(dal, "OgSetting")?
            .update_by_pk(session.as_mut(), &fields, &[DbValue::Int(id)])
            .map_err(|e| format!("更新设置项失败：{e}"))?;
    } else {
        let fields: Vec<(&str, DbValue)> = vec![
            ("Name", DbValue::Text(name.to_string())),
            ("Value", DbValue::Text(value.to_string())),
            ("UpdateTime", dt(now)),
        ];
        table(dal, "OgSetting")?
            .insert(session.as_mut(), &fields)
            .map_err(|e| format!("写入设置项失败：{e}"))?;
    }
    Ok(())
}

/// 把所有规则集版本 +1，返回新的最大版本。
///
/// 用途：**服务端配置（WatchRoots/排除项/公司信息/密级/离线宽限/允许卸载）变更时**，
/// 这些内容不在"规则 JSON"里，`save_policy` 的比较看不出变化、版本不会涨，
/// 客户端心跳就永远认为"策略没变"→ 配置改了不生效。这里显式推一版。
pub fn bump_all_policies(store: &SharedStore) -> Result<u32, String> {
    let dal = store.dal();
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    table(dal, "OgPolicySet")?
        .increment(
            session.as_mut(),
            &[("Version", DbValue::Int(1))],
            &Where::new().ge("Id", DbValue::Int(0)),
        )
        .map_err(|e| format!("提升规则集版本失败：{e}"))?;
    policy_bundle_version(store)
}

/// 最近事件（面板视图；按时间倒序）。
pub fn list_events(store: &SharedStore, limit: usize) -> Result<Vec<Value>, String> {
    let dal = store.dal();
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    let query = Query::new().take(limit);
    let set = table(dal, "OgClientEvent")?
        .query(session.as_mut(), &query)
        .map_err(|e| format!("查询事件失败：{e}"))?;

    let mut rows: Vec<(String, Value)> = set
        .rows
        .iter()
        .map(|row| {
            let time = db_text(row.get_by_name("ReceivedAt"));
            (
                time.clone(),
                json!({
                    "eventId": db_text(row.get_by_name("EventId")),
                    "clientId": db_text(row.get_by_name("ClientId")),
                    "eventType": db_text(row.get_by_name("EventType")),
                    "occurredAt": db_text(row.get_by_name("OccurredAt")),
                    "receivedAt": time,
                    "path": db_text(row.get_by_name("Path")),
                    "ruleId": db_text(row.get_by_name("RuleId")),
                    "user": db_text(row.get_by_name("UserName")),
                    "processName": db_text(row.get_by_name("ProcessName")),
                    "size": db_int(row.get_by_name("Size")),
                    "detail": db_text(row.get_by_name("Detail")),
                }),
            )
        })
        .collect();
    rows.sort_by_key(|item| std::cmp::Reverse(item.0.clone()));
    Ok(rows.into_iter().map(|(_, value)| value).collect())
}

/// 事件总数。
pub fn event_count(store: &SharedStore) -> Result<i64, String> {
    let dal = store.dal();
    let mut session = dal.open_session().map_err(|e| format!("打开会话失败：{e}"))?;
    table(dal, "OgClientEvent")?
        .count(session.as_mut(), None)
        .map_err(|e| format!("统计事件失败：{e}"))
}
