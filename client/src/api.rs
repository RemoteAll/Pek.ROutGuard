//! 服务端接口（阻塞 HTTP）：注册 / 心跳 / 拉策略 / 上报事件。

use std::time::Duration;

use pek_outguard_core::protocol::{
    EventsRequest, EventsResponse, HeartbeatRequest, HeartbeatResponse, PolicyBundle,
    RegisterRequest, RegisterResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// 客户端 API（每个请求独立构造，无线程状态）。
pub struct Api {
    /// 服务端基地址（无尾部斜杠）
    pub base: String,
    /// 超时
    pub timeout: Duration,
}

impl Api {
    /// 从配置构造（校验协议前缀）。
    pub fn new(server_url: &str) -> Result<Self, String> {
        let url = server_url.trim().trim_end_matches('/');
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!(
                "ServerUrl 必须以 http:// 或 https:// 开头（当前：{url}）"
            ));
        }
        Ok(Self {
            base: url.to_string(),
            timeout: Duration::from_secs(15),
        })
    }

    /// `POST /api/client/register`
    pub fn register(&self, request: &RegisterRequest) -> Result<RegisterResponse, String> {
        self.request("POST", "/api/client/register", &[], Some(request))
    }

    /// `POST /api/client/heartbeat`
    pub fn heartbeat(
        &self,
        client_id: &str,
        token: &str,
        request: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, String> {
        let headers = [
            ("X-OG-Client", client_id),
            ("X-OG-Token", token),
        ];
        self.request("POST", "/api/client/heartbeat", &headers, Some(request))
    }

    /// `GET /api/client/policy`
    pub fn policy(&self, client_id: &str, token: &str) -> Result<PolicyBundle, String> {
        let headers = [
            ("X-OG-Client", client_id),
            ("X-OG-Token", token),
        ];
        self.request::<(), PolicyBundle>("GET", "/api/client/policy", &headers, None)
    }

    /// `POST /api/client/events`
    pub fn events(
        &self,
        client_id: &str,
        token: &str,
        request: &EventsRequest,
    ) -> Result<EventsResponse, String> {
        let headers = [
            ("X-OG-Client", client_id),
            ("X-OG-Token", token),
        ];
        self.request("POST", "/api/client/events", &headers, Some(request))
    }

    fn request<B: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&B>,
    ) -> Result<T, String> {
        let url = format!("{}{}", self.base, path);
        let payload = match body {
            Some(value) => serde_json::to_vec(value)
                .map_err(|e| format!("请求序列化失败（{path}）：{e}"))?,
            None => Vec::new(),
        };
        let response = dhrust::net::http_client::blocking_request(
            method,
            &url,
            headers,
            Some("application/json"),
            payload,
            self.timeout,
        )
        .map_err(|e| format!("请求 {path} 失败：{e}"))?;

        let text = String::from_utf8_lossy(&response.body).to_string();
        if response.status != 200 {
            let message = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|value| {
                    value
                        .get("error")
                        .and_then(|error| error.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| {
                    if text.trim().is_empty() {
                        format!("HTTP {}", response.status)
                    } else {
                        text.chars().take(200).collect()
                    }
                });
            return Err(format!("{}（HTTP {}）", message, response.status));
        }

        serde_json::from_str(&text).map_err(|e| format!("响应解析失败（{path}）：{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_scheme() {
        assert!(Api::new("127.0.0.1:5600").is_err());
        assert!(Api::new("").is_err());
        assert!(Api::new("http://127.0.0.1:5600").is_ok());
        assert_eq!(
            Api::new("https://host:5600/").expect("ok").base,
            "https://host:5600"
        );
    }
}
