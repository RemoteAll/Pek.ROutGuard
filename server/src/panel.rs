//! 面板与路由：登录、概览、终端准入、规则集、事件。
//!
//! - 路由 / 静态资源：`dhrust::net::{router, static_files}`
//! - 鉴权：`dhrust::net::panel_auth`（`AuthLevel` / `bearer_token` / `client_ip`）
//! - 登录限流：`dhrust::net::login_guard`
//! - `res/index.html` 为 `include_bytes!` 内嵌，改动后需 touch 本文件重编。

use std::sync::Arc;

use dhrust::net::http::{HttpOutcome, HttpResponse};
use dhrust::net::panel_auth::{AuthLevel, bearer_token, client_ip, is_loopback};
use dhrust::net::router::{Ctx, RouteHandler, Router, route};
use dhrust::net::static_files::StaticFiles;
use pek_outguard_core::rules::{Action, PolicySet, Rule};
use serde_json::{Map, Value, json};

use crate::app::{App, PanelSession};
use crate::client_api;
use crate::db;

fn statics() -> StaticFiles {
    StaticFiles::new("wwwroot")
        .embed(
            "/index.html",
            include_bytes!("../res/index.html"),
            "text/html; charset=utf-8",
        )
        .spa_fallback(true)
        .spa_excludes(&["/api"])
}

/// 组装全部路由。
pub fn build_router(app: Arc<App>) -> Router {
    let mut router = Router::new();

    router.map_post("/api/login", login(Arc::clone(&app)));
    router.map_post("/api/logout", logout(Arc::clone(&app)));

    router.map_get("/api/status", guard(Arc::clone(&app), status));
    router.map_get("/api/clients", guard(Arc::clone(&app), clients));
    router.map_post("/api/client/status", guard(Arc::clone(&app), set_client_status));
    router.map_get("/api/policies", guard(Arc::clone(&app), policies));
    router.map_post("/api/policy", guard(Arc::clone(&app), save_policy));
    router.map_get("/api/events", guard(Arc::clone(&app), events));

    // 客户端协议（令牌鉴权，不走面板登录）
    router.map_post("/api/client/register", client_api::register(Arc::clone(&app)));
    router.map_post("/api/client/heartbeat", client_api::heartbeat(Arc::clone(&app)));
    router.map_get("/api/client/policy", client_api::policy(Arc::clone(&app)));
    router.map_post("/api/client/events", client_api::events(Arc::clone(&app)));

    let statics = statics();
    router.fallback(route(move |ctx: Ctx| {
        let statics = statics.clone();
        async move {
            let method_ok = ctx.req.method.eq_ignore_ascii_case("GET")
                || ctx.req.method.eq_ignore_ascii_case("HEAD");
            if method_ok {
                if let Some(response) = statics.try_serve_request(&ctx.req) {
                    return HttpOutcome::Response(response);
                }
            } else if let Some(response) = statics.try_serve_file(&ctx.req.path) {
                return HttpOutcome::Response(response);
            }
            HttpOutcome::Response(fail(404, "未知路由"))
        }
    }));

    dhrust::info!("路由已组装：面板 + 客户端接口");
    router
}

// ————— 登录 —————

fn login(app: Arc<App>) -> RouteHandler {
    route(move |ctx: Ctx| {
        let app = Arc::clone(&app);
        async move {
            let ip = client_ip(&ctx);
            if app.login_guard.is_blocked(&ip) {
                return HttpOutcome::Response(fail(429, "登录尝试过多，请稍后再试"));
            }

            let body = json_body(&ctx);
            let user = text(&body, "user");
            let password = text(&body, "password");
            if user.is_empty() || password.is_empty() {
                return HttpOutcome::Response(fail(400, "用户名与密码不能为空"));
            }

            match app.verify_login(&user, &password) {
                Some(session) => {
                    app.login_guard.record_success(&ip);
                    let token = app.tokens.issue_with(session.clone());
                    dhrust::info!("面板登录成功：user={user} ip={ip}");
                    HttpOutcome::Response(ok(json!({ "token": token, "user": session.user })))
                }
                None => {
                    app.login_guard.record_failure(&ip);
                    dhrust::warn!("面板登录失败：user={user} ip={ip}");
                    HttpOutcome::Response(fail(401, "用户名或密码错误"))
                }
            }
        }
    })
}

fn logout(app: Arc<App>) -> RouteHandler {
    route(move |ctx: Ctx| {
        let app = Arc::clone(&app);
        async move {
            if let Some(token) = bearer_token(&ctx) {
                app.tokens.revoke(&token);
            }
            HttpOutcome::Response(ok(json!({ "loggedOut": true })))
        }
    })
}

// ————— 鉴权 —————

fn guard(app: Arc<App>, handler: fn(&App, &Ctx) -> HttpResponse) -> RouteHandler {
    route(move |ctx: Ctx| {
        let app = Arc::clone(&app);
        async move {
            match require(&app, &ctx) {
                Ok(_session) => HttpOutcome::Response(handler(&app, &ctx)),
                Err(response) => HttpOutcome::Response(response),
            }
        }
    })
}

fn require(app: &App, ctx: &Ctx) -> Result<PanelSession, HttpResponse> {
    if let Some(token) = bearer_token(ctx)
        && let Some(session) = app.tokens.get(&token)
    {
        app.tokens.touch(&token);
        return Ok(session);
    }

    let level = AuthLevel::parse(&app.server().web_auth_level);
    let ip = client_ip(ctx);
    let local = is_loopback(&ip);
    match level {
        AuthLevel::None if local => Ok(PanelSession {
            user: "local".into(),
            builtin: true,
        }),
        AuthLevel::LocalOnly if local => Ok(PanelSession {
            user: "local".into(),
            builtin: true,
        }),
        _ => Err(fail(401, "需要登录")),
    }
}

// ————— 面板 API —————

fn status(app: &App, _ctx: &Ctx) -> HttpResponse {
    let server = app.server();
    let (total, online, pending) = db::client_stats(&app.store).unwrap_or((0, 0, 0));
    let policies = db::list_policies(&app.store)
        .map(|items| items.len())
        .unwrap_or(0);
    let events = db::event_count(&app.store).unwrap_or(0);
    let default_password = crate::config::verify_password(&server.web_password_hash, "admin")
        && server.web_user_name == "admin";

    ok(json!({
        "version": crate::VERSION,
        "product": crate::PRODUCT,
        "uptimeSecs": app.uptime_secs(),
        "server": {
            "host": server.host,
            "port": server.port,
            "allowRemote": server.allow_remote,
            "webUserName": server.web_user_name,
            "webAuthLevel": server.web_auth_level,
            "companyName": server.company_name,
            "autoApprove": server.auto_approve,
            "watchRoots": server.watch_roots,
            "defaultPassword": default_password,
        },
        "stats": {
            "clients": total,
            "online": online,
            "pending": pending,
            "policies": policies,
            "events": events,
        }
    }))
}

fn clients(app: &App, ctx: &Ctx) -> HttpResponse {
    let limit = ctx
        .query_value("limit")
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(200)
        .min(1000);
    match db::list_clients(&app.store, limit) {
        Ok(items) => ok(json!(items)),
        Err(e) => fail(500, &e),
    }
}

fn set_client_status(app: &App, ctx: &Ctx) -> HttpResponse {
    let body = json_body(ctx);
    let client_id = text(&body, "clientId");
    let status = text(&body, "status");
    if client_id.is_empty() {
        return fail(400, "clientId 不能为空");
    }
    if !matches!(status.as_str(), "active" | "pending" | "rejected" | "disabled") {
        return fail(400, "status 只能是 active / pending / rejected / disabled");
    }
    match db::set_client_status(&app.store, &client_id, &status) {
        Ok(true) => {
            dhrust::info!("终端状态更新：client={client_id} status={status}");
            ok(json!({ "clientId": client_id, "status": status }))
        }
        Ok(false) => fail(404, "终端不存在"),
        Err(e) => fail(500, &e),
    }
}

fn policies(app: &App, _ctx: &Ctx) -> HttpResponse {
    match db::list_policies(&app.store) {
        Ok(items) => {
            let list: Vec<Value> = items
                .into_iter()
                .map(|(policy, enabled, remark)| {
                    json!({
                        "id": policy.id,
                        "name": policy.name,
                        "version": policy.version,
                        "keyVersion": policy.key_version,
                        "defaultAction": policy.default_action.as_str(),
                        "excludePaths": policy.exclude_paths,
                        "rules": policy.rules,
                        "enabled": enabled,
                        "remark": remark,
                    })
                })
                .collect();
            ok(json!(list))
        }
        Err(e) => fail(500, &e),
    }
}

fn save_policy(app: &App, ctx: &Ctx) -> HttpResponse {
    let body = json_body(ctx);
    if body.as_object().is_none_or(|map| map.is_empty()) {
        return fail(400, "请求体不是合法 JSON 对象");
    }
    let id = text(&body, "id");
    let name = text(&body, "name");
    if id.is_empty() || name.is_empty() {
        return fail(400, "id 与 name 不能为空");
    }

    let default_action = match text(&body, "defaultAction").as_str() {
        "encrypt" => Action::Encrypt,
        "block_write" => Action::BlockWrite,
        "audit" => Action::Audit,
        _ => Action::Plaintext,
    };
    let exclude_paths: Vec<String> = body
        .get("excludePaths")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let rules: Vec<Rule> = match body.get("rules") {
        Some(value) => match serde_json::from_value(value.clone()) {
            Ok(rules) => rules,
            Err(e) => return fail(400, &format!("规则格式错误：{e}")),
        },
        None => Vec::new(),
    };
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let remark = text(&body, "remark");

    let policy = PolicySet {
        id,
        name,
        version: 1,
        key_version: 1,
        default_action,
        exclude_paths,
        rules,
    };

    match db::save_policy(&app.store, &policy, enabled, &remark) {
        Ok(version) => {
            dhrust::info!("规则集已保存：id={} version={version}", policy.id);
            ok(json!({ "id": policy.id, "version": version, "enabled": enabled }))
        }
        Err(e) => fail(400, &e),
    }
}

fn events(app: &App, ctx: &Ctx) -> HttpResponse {
    let limit = ctx
        .query_value("limit")
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(100)
        .min(500);
    match db::list_events(&app.store, limit) {
        Ok(items) => ok(json!(items)),
        Err(e) => fail(500, &e),
    }
}

// ————— 辅助 —————

fn json_body(ctx: &Ctx) -> Value {
    serde_json::from_slice(&ctx.req.body).unwrap_or_else(|_| Value::Object(Map::new()))
}

fn text(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn ok(data: Value) -> HttpResponse {
    HttpResponse::json(200, json!({ "ok": true, "data": data }).to_string())
}

fn fail(status: u16, message: &str) -> HttpResponse {
    HttpResponse::json(status, json!({ "ok": false, "message": message }).to_string())
}
