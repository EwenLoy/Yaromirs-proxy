//! rproxy-mcp — MCP-сервер (stdio JSON-RPC) поверх сессии прокси (tech-plan.md §9, M2.5).
//! Headless: агент (Claude Code / Codex / Cursor) подключается к работающему `rproxy run --mcp`
//! и читает/управляет трафиком без GUI.

use rproxy_core::Exchange;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Общая сессия: накопленные exchanges + флаг записи.
#[derive(Clone, Default)]
pub struct Store {
    pub session: Arc<Mutex<Vec<Exchange>>>,
    pub recording: Arc<AtomicBool>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            session: Arc::new(Mutex::new(Vec::new())),
            recording: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_recording(&self) -> bool {
        self.recording.load(Ordering::Relaxed)
    }
}

const BODY_LIMIT: usize = 20_000;

fn trunc(s: &str) -> String {
    if s.len() > BODY_LIMIT {
        format!("{}\n…[truncated {} chars]", &s[..BODY_LIMIT], s.len() - BODY_LIMIT)
    } else {
        s.to_string()
    }
}

fn body_of(ex: &Exchange, response: bool) -> String {
    let b = if response {
        ex.response_body_decoded.as_ref().or(ex.response_body.as_ref())
    } else {
        ex.request_body.as_ref()
    };
    b.as_ref()
        .map(|b| trunc(&String::from_utf8_lossy(b)))
        .unwrap_or_default()
}

fn flow_summary(i: usize, ex: &Exchange) -> Value {
    let (method, uri) = ex
        .request
        .as_ref()
        .map(|r| (r.method.clone(), r.uri.clone()))
        .unwrap_or_else(|| ("-".into(), "-".into()));
    json!({
        "index": i,
        "id": ex.id.0,
        "method": method,
        "url": uri,
        "status": ex.response_status,
        "duration": ex.timing.total().map(|d| d.as_millis() as u64),
        "error": ex.error,
    })
}

fn to_curl(ex: &Exchange) -> String {
    let Some(r) = &ex.request else { return String::new() };
    let mut parts = vec![format!("curl -X {}", r.method)];
    if let Some(body) = &ex.request_body {
        if !body.is_empty() {
            parts.push(format!(
                "-d {}",
                serde_json::to_string(&String::from_utf8_lossy(body)).unwrap_or_default()
            ));
        }
    }
    for (k, v) in &r.headers {
        let kl = k.to_lowercase();
        if kl == "host" || kl == "content-length" {
            continue;
        }
        parts.push(format!("-H {}", serde_json::to_string(&format!("{k}: {v}")).unwrap_or_default()));
    }
    parts.push(serde_json::to_string(&r.uri).unwrap_or_default());
    parts.join(" \\\n  ")
}

fn tools_list() -> Value {
    let tools = [
        ("get_flows", "List captured HTTP flows (optional filter substring and limit)", json!({
            "type": "object",
            "properties": {
                "filter": { "type": "string" },
                "limit": { "type": "integer" }
            }
        })),
        ("get_flow", "Full details of one flow by index: headers and bodies", json!({
            "type": "object",
            "properties": { "index": { "type": "integer" } },
            "required": ["index"]
        })),
        ("export_flow_curl", "Export a flow as a cURL command by index", json!({
            "type": "object",
            "properties": { "index": { "type": "integer" } },
            "required": ["index"]
        })),
        ("toggle_recording", "Start/stop capturing new flows", json!({ "type": "object", "properties": {} })),
        ("clear_session", "Remove all captured flows", json!({ "type": "object", "properties": {} })),
        ("get_status", "Session status: flow count, recording flag", json!({ "type": "object", "properties": {} })),
    ];
    json!(tools.iter().map(|(n, d, s)| json!({
        "name": n, "description": d, "inputSchema": s
    })).collect::<Vec<_>>())
}

fn text_result(text: impl Into<String>) -> Value {
    json!({ "content": [ { "type": "text", "text": text.into() } ] })
}

#[doc(hidden)]
pub async fn call_tool(store: &Store, name: &str, args: Value) -> Value {
    match name {
        "get_status" => text_result(serde_json::to_string(&json!({
            "flows": store.session.lock().unwrap().len(),
            "recording": store.is_recording(),
            "version": env!("CARGO_PKG_VERSION"),
        })).unwrap_or_default()),

        "clear_session" => {
            store.session.lock().unwrap().clear();
            text_result("session cleared")
        }

        "toggle_recording" => {
            let now = !store.is_recording();
            store.recording.store(now, Ordering::Relaxed);
            text_result(if now { "recording ON" } else { "recording OFF" })
        }

        "get_flows" => {
            let filter = args["filter"].as_str().unwrap_or("").to_lowercase();
            let limit = args["limit"].as_u64().unwrap_or(50) as usize;
            let session = store.session.lock().unwrap();
            let items: Vec<Value> = session
                .iter()
                .enumerate()
                .filter(|(_, ex)| {
                    filter.is_empty()
                        || ex.request.as_ref().map_or(false, |r| {
                            r.uri.to_lowercase().contains(&filter)
                                || r.method.to_lowercase().contains(&filter)
                        })
                })
                .map(|(i, ex)| flow_summary(i, ex))
                .collect();
            let skip = items.len().saturating_sub(limit);
            text_result(serde_json::to_string_pretty(&json!({
                "total": items.len(),
                "flows": &items[skip..],
            })).unwrap_or_default())
        }

        "get_flow" => {
            let idx = args["index"].as_u64().unwrap_or(u64::MAX) as usize;
            let session = store.session.lock().unwrap();
            match session.get(idx) {
                Some(ex) => text_result(serde_json::to_string_pretty(&json!({
                    "flow": flow_summary(idx, ex),
                    "request_headers": ex.request.as_ref().map(|r| r.headers.clone()).unwrap_or_default(),
                    "request_body": body_of(ex, false),
                    "response_status": ex.response_status,
                    "response_headers": ex.response_headers,
                    "response_content_type": ex.response_content_type,
                    "response_body": body_of(ex, true),
                    "error": ex.error,
                })).unwrap_or_default()),
                None => text_result(format!("no flow at index {idx}")),
            }
        }

        "export_flow_curl" => {
            let idx = args["index"].as_u64().unwrap_or(u64::MAX) as usize;
            let session = store.session.lock().unwrap();
            match session.get(idx) {
                Some(ex) => text_result(to_curl(ex)),
                None => text_result(format!("no flow at index {idx}")),
            }
        }

        other => text_result(format!("unknown tool: {other}")),
    }
}


/// Запуск MCP-сервера над stdin/stdout (блокирует до EOF на stdin).
pub async fn serve(store: Store) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    eprintln!("[rproxy-mcp] MCP server ready on stdio");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // не JSON — игнорируем
        };
        let id = msg.get("id").cloned();
        let method = msg["method"].as_str().unwrap_or("").to_string();

        let result = match method.as_str() {
            "initialize" => {
                let pv = {
                    let v = &msg["params"]["protocolVersion"];
                    if v.is_null() { json!("2025-06-18") } else { v.clone() }
                };
                json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "rproxy", "version": env!("CARGO_PKG_VERSION") },
                })
            }
            "tools/list" => json!({ "tools": tools_list() }),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or("").to_string();
                call_tool(&store, &name, msg["params"]["arguments"].clone()).await
            }
            // notifications (initialized и т.п.) — ответа не требуют
            _ if id.is_none() => continue,
            _ => json!({ "error": { "code": -32601, "message": format!("method not found: {method}") } }),
        };

        if let Some(id) = id {
            let resp = json!({ "jsonrpc": "2.0", "id": id, "result": result });
            stdout.write_all(resp.to_string().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    eprintln!("[rproxy-mcp] stdin closed, MCP server stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rproxy_core::{ConnectionId, ExchangeId, Protocol};

    fn fake_exchange() -> Exchange {
        let mut ex = Exchange::new(ExchangeId(1), ConnectionId(1), Protocol::Http1);
        ex.request = Some(rproxy_core::HttpRequest {
            method: "POST".into(),
            uri: "http://api.test/login".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            is_connect: false,
        });
        ex.request_body = Some(bytes::Bytes::from_static(br#"{"user":"admin"}"#));
        ex.response_status = Some(200);
        ex.response_body = Some(bytes::Bytes::from_static(br#"{"token":"abc"}"#));
        ex
    }

    #[tokio::test]
    async fn tools_work() {
        let store = Store::new();
        store.session.lock().unwrap().push(fake_exchange());

        let status = call_tool(&store, "get_status", json!({})).await;
        assert!(status["content"][0]["text"].as_str().unwrap().contains("flows"));

        let flows = call_tool(&store, "get_flows", json!({"filter": "api.test"})).await;
        let text = flows["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("api.test"));
        assert!(text.contains("\"total\": 1"));

        let none = call_tool(&store, "get_flows", json!({"filter": "nomatch"})).await;
        assert!(none["content"][0]["text"].as_str().unwrap().contains("\"total\": 0"));

        let flow = call_tool(&store, "get_flow", json!({"index": 0})).await;
        let text = flow["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("admin"));
        assert!(text.contains("abc"));

        let curl = call_tool(&store, "export_flow_curl", json!({"index": 0})).await;
        let text = curl["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("curl -X POST"));
        assert!(text.contains("http://api.test/login"));

        call_tool(&store, "toggle_recording", json!({})).await;
        assert!(!store.is_recording());

        call_tool(&store, "clear_session", json!({})).await;
        assert!(store.session.lock().unwrap().is_empty());
    }
}


