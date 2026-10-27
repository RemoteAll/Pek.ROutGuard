//! 客户端接口：注册 / 心跳 / 拉策略 / 上报事件。
//!
//! 身份：`X-OG-Client`（终端 ID）+ `X-OG-Token`（注册时下发的一次性令牌）。
//! **M2 升级**：改为 `X-OG-Timestamp/Nonce/Signature` 的 Ed25519 签名（core 已提供 `signature_payload`），
//! 令牌仅作为注册凭据。

use std::sync::Arc;

use base64::Engine as _;
use dhrust::net::http::{HttpOutcome, HttpResponse};
use dhrust::net::router::{Ctx, RouteHandler, route};
use pek_outguard_core::crypto;
use pek_outguard_core::protocol::{
    ClientCommand, ClientStatus, EventsRequest, EventsResponse, HeartbeatRequest, HeartbeatResponse,
    PolicyBundle, RegisterRequest, RegisterResponse, WrappedPolicyKey,
};
use pek_outguard_core::rules::PolicySet;
use serde_json::json;

use crate::app::App;
use crate::db::{self, ClientRecord};

const TOKEN_HEADER: &str = "x-og-token";
const CLIENT_HEADER: &str = "x-og-client";

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn error(status: u16, message: &str) -> HttpOutcome {
    HttpOutcome::Response(HttpResponse::json(
        status,
        json!({ "error": message }).to_string(),
    ))
}

fn json_error(status: u16, message: &str) -> HttpResponse {
    HttpResponse::json(status, json!({ "error": message }).to_string())
}

fn header(ctx: &Ctx, name: &str) -> String {
    ctx.req.header(name).unwrap_or_default().trim().to_string()
}

fn parse_status(text: &str) -> ClientStatus {
    match text {
        "active" => ClientStatus::Active,
        "rejected" => ClientStatus::Rejected,
        "disabled" => ClientStatus::Disabled,
        _ => ClientStatus::Pending,
    }
}

/// 鉴权：终端 ID + 令牌（与库中哈希比对）+ 状态必须 `active`。
fn authenticate(app: &App, client_id: &str, token: &str) -> Result<ClientRecord, HttpResponse> {
    if client_id.is_empty() || token.is_empty() {
        return Err(json_error(401, "缺少终端身份（X-OG-Client / X-OG-Token）"));
    }
    let record = db::find_by_client_id(&app.store, client_id)
        .map_err(|e| json_error(500, &e))?
        .ok_or_else(|| json_error(401, "终端未注册"))?;

    let hash = crypto::hex(&crypto::sha256(token.as_bytes()));
    if hash != record.token_hash {
        return Err(json_error(401, "终端令牌无效"));
    }

    match record.status.as_str() {
        "active" => Ok(record),
        "pending" => Err(json_error(403, "终端待管理员准入")),
        "rejected" => Err(json_error(403, "终端已被拒绝")),
        "disabled" => Err(json_error(403, "终端已被禁用")),
        other => Err(json_error(403, &format!("终端状态异常：{other}"))),
    }
}

/// `POST /api/client/register`：注册（幂等；重复安装会换发令牌）。
pub fn register(app: Arc<App>) -> RouteHandler {
    route(move |ctx: Ctx| {
        let app = Arc::clone(&app);
        async move {
            let request: RegisterRequest = match serde_json::from_slice(&ctx.req.body) {
                Ok(value) => value,
                Err(e) => return error(400, &format!("注册报文解析失败：{e}")),
            };
            if request.machine_id.trim().is_empty() {
                return error(400, "machineId 不能为空");
            }
            if request.public_key.trim().is_empty() {
                return error(400, "publicKey 不能为空");
            }

            let server = app.server();
            let existing = match db::find_by_machine(&app.store, &request.machine_id) {
                Ok(value) => value,
                Err(e) => return error(500, &e),
            };
            let (client_id, status) = match &existing {
                Some(record) => (record.client_id.clone(), record.status.clone()),
                None => (
                    format!(
                        "c-{}",
                        request
                            .machine_id
                            .chars()
                            .filter(|ch| ch.is_ascii_hexdigit())
                            .take(16)
                            .collect::<String>()
                    ),
                    if server.auto_approve {
                        "active".to_string()
                    } else {
                        "pending".to_string()
                    },
                ),
            };

            let token = dhrust::random::hex(16);
            let token_hash = crypto::hex(&crypto::sha256(token.as_bytes()));
            if let Err(e) = db::upsert_registration(
                &app.store,
                &request,
                &client_id,
                &token_hash,
                &status,
            ) {
                return error(500, &e);
            }

            let response = RegisterResponse {
                client_id,
                client_token: token,
                status: parse_status(&status),
                server_time: now_secs(),
            };
            dhrust::info!(
                "终端注册：machineId={} host={} status={status}",
                request.machine_id,
                request.hostname
            );
            HttpOutcome::Response(HttpResponse::json(
                200,
                serde_json::to_string(&response).unwrap_or_default(),
            ))
        }
    })
}

/// `POST /api/client/heartbeat`：心跳（只发变化项）。
pub fn heartbeat(app: Arc<App>) -> RouteHandler {
    route(move |ctx: Ctx| {
        let app = Arc::clone(&app);
        async move {
            let request: HeartbeatRequest = match serde_json::from_slice(&ctx.req.body) {
                Ok(value) => value,
                Err(e) => return error(400, &format!("心跳报文解析失败：{e}")),
            };
            let client = match authenticate(&app, &request.client_id, &header(&ctx, TOKEN_HEADER)) {
                Ok(record) => record,
                Err(response) => return HttpOutcome::Response(response),
            };

            if let Err(e) = db::apply_heartbeat(&app.store, &client, &request, db::now()) {
                return error(500, &e);
            }

            let policy_version = db::policy_bundle_version(&app.store).unwrap_or(0);
            let mut commands = Vec::new();
            if request.policy_version != policy_version {
                commands.push(ClientCommand::SyncPolicy);
            }

            let response = HeartbeatResponse {
                server_time: now_secs(),
                policy_version,
                commands,
            };
            HttpOutcome::Response(HttpResponse::json(
                200,
                serde_json::to_string(&response).unwrap_or_default(),
            ))
        }
    })
}

/// `GET /api/client/policy`：下发策略包（规则集 + 包裹后的策略密钥）。
pub fn policy(app: Arc<App>) -> RouteHandler {
    route(move |ctx: Ctx| {
        let app = Arc::clone(&app);
        async move {
            let client_id = header(&ctx, CLIENT_HEADER);
            let token = header(&ctx, TOKEN_HEADER);
            let client = match authenticate(&app, &client_id, &token) {
                Ok(record) => record,
                Err(response) => return HttpOutcome::Response(response),
            };

            match build_policy_bundle(&app, &token) {
                Ok(bundle) => {
                    dhrust::info!(
                        "策略下发：client={} version={} policies={}",
                        client.client_id,
                        bundle.version,
                        bundle.policy_sets.len()
                    );
                    HttpOutcome::Response(HttpResponse::json(
                        200,
                        serde_json::to_string(&bundle).unwrap_or_default(),
                    ))
                }
                Err(e) => error(500, &e),
            }
        }
    })
}

/// `POST /api/client/events`：批量上报审计事件（单批 ≤ 200，按 EventId 幂等）。
pub fn events(app: Arc<App>) -> RouteHandler {
    route(move |ctx: Ctx| {
        let app = Arc::clone(&app);
        async move {
            let client_id = header(&ctx, CLIENT_HEADER);
            let token = header(&ctx, TOKEN_HEADER);
            let client = match authenticate(&app, &client_id, &token) {
                Ok(record) => record,
                Err(response) => return HttpOutcome::Response(response),
            };

            let request: EventsRequest = match serde_json::from_slice(&ctx.req.body) {
                Ok(value) => value,
                Err(e) => return error(400, &format!("事件报文解析失败：{e}")),
            };
            if request.events.len() > 200 {
                return error(400, "单批事件不能超过 200 条");
            }

            match db::insert_events(&app.store, &client.client_id, &request.events) {
                Ok((accepted, duplicated)) => {
                    let response = EventsResponse {
                        accepted,
                        duplicated,
                        rejected: 0,
                    };
                    HttpOutcome::Response(HttpResponse::json(
                        200,
                        serde_json::to_string(&response).unwrap_or_default(),
                    ))
                }
                Err(e) => error(500, &e),
            }
        }
    })
}

/// 组装策略包：全部启用规则集（M1 暂不做组绑定）+ 包裹后的策略密钥。
pub fn build_policy_bundle(app: &App, client_token: &str) -> Result<PolicyBundle, String> {
    let server = app.server();
    let all = db::list_policies(&app.store)?;
    let mut policies: Vec<PolicySet> = all
        .iter()
        .filter(|(_, enabled, _)| *enabled)
        .map(|(policy, _, _)| policy.clone())
        .collect();
    if policies.is_empty() {
        policies.push(PolicySet::builtin_default());
    }

    let version = policies.iter().map(|policy| policy.version).max().unwrap_or(0);
    let mut wrapped_keys = Vec::with_capacity(policies.len());
    for policy in &policies {
        let key = crypto::derive_policy_key(&app.master, &policy.id, policy.key_version)
            .map_err(|e| e.to_string())?;
        let packed = crypto::wrap_for_client(client_token, &key).map_err(|e| e.to_string())?;
        wrapped_keys.push(WrappedPolicyKey {
            policy_id: policy.id.clone(),
            key_version: policy.key_version,
            wrapped_key: base64::engine::general_purpose::STANDARD.encode(packed),
        });
    }

    let mut exclude_paths = server.exclude_paths.clone();
    let temp_dir = "C:\\ProgramData\\Pek\\OutGuard\\temp".to_string();
    if !exclude_paths.iter().any(|path| path == &temp_dir) {
        exclude_paths.push(temp_dir);
    }

    Ok(PolicyBundle {
        version,
        policy_sets: policies,
        wrapped_keys,
        watch_roots: server.watch_roots.clone(),
        exclude_paths,
        container_ext: pek_outguard_core::CONTAINER_EXT.to_string(),
        company: server.company_name.clone(),
        notice: server.notice.clone(),
        classification: server.classification.clone(),
        allow_uninstall: server.allow_uninstall,
        offline_grace_days: server.offline_grace_days,
        server_time: now_secs(),
    })
}
