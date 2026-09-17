//! rproxy-export — экспорт сессий (HAR и др.), tech-plan.md §6.

use rproxy_core::Exchange;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn rfc3339(t: Option<std::time::SystemTime>) -> String {
    let dt = t
        .map(OffsetDateTime::from)
        .unwrap_or_else(OffsetDateTime::now_utc);
    dt.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn headers_json(headers: &[(String, String)]) -> Value {
    headers
        .iter()
        .map(|(k, v)| json!({ "name": k, "value": v }))
        .collect()
}

fn body_text(body: &Option<bytes::Bytes>) -> Value {
    match body {
        Some(b) => json!(String::from_utf8_lossy(b)),
        None => json!(""),
    }
}

fn exchange_to_entry(ex: &Exchange) -> Value {
    let (method, url, req_headers) = ex
        .request
        .as_ref()
        .map(|r| (r.method.clone(), r.uri.clone(), r.headers.clone()))
        .unwrap_or_else(|| ("-".into(), "-".into(), Vec::new()));

    let status = ex.response_status.unwrap_or(0);
    let mime = ex.response_content_type.clone().unwrap_or_default();

    let req_body_size = ex.request_body.as_ref().map_or(-1i64, |b| b.len() as i64);
    let resp_body_size = ex.response_body.as_ref().map_or(-1i64, |b| b.len() as i64);

    json!({
        "startedDateTime": rfc3339(ex.started_wall),
        "time": ex.timing.total().map(|d| d.as_millis() as u64).unwrap_or(0),
        "_state": format!("{:?}", ex.state),
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": headers_json(&req_headers),
            "queryString": [],
            "headersSize": -1,
            "bodySize": req_body_size,
            "postData": {
                "mimeType": req_headers.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default(),
                "text": ex.request_body.as_ref()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .unwrap_or_default(),
            },
        },
        "response": {
            "status": status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": headers_json(&ex.response_headers),
            "content": {
                "size": resp_body_size,
                "mimeType": mime,
                "text": body_text(&ex.response_body_decoded.clone().or_else(|| ex.response_body.clone())),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": resp_body_size,
        },
        "cache": {},
        "timings": {
            "send": 0,
            "wait": ex.timing.total().map(|d| d.as_millis() as f64).unwrap_or(0.0),
            "receive": 0,
        },
        "_error": ex.error,
    })
}

/// Экспорт списка Exchange в HAR 1.2 (строка JSON).
pub fn to_har(exchanges: &[Exchange]) -> String {
    let har = json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "rproxy", "version": env!("CARGO_PKG_VERSION") },
            "entries": exchanges.iter().map(exchange_to_entry).collect::<Vec<Value>>(),
        }
    });
    serde_json::to_string_pretty(&har).expect("har serialization")
}

/// Записать HAR в файл.
pub fn write_har(path: impl AsRef<std::path::Path>, exchanges: &[Exchange]) -> std::io::Result<()> {
    std::fs::write(path, to_har(exchanges))
}
