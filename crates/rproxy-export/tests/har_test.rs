//! Тест rproxy-export: HAR-сериализация.

use rproxy_core::{Exchange, ExchangeId, ConnectionId, Protocol, HttpRequest};

#[test]
fn har_export_contains_entries() {
    let mut ex = Exchange::new(ExchangeId(1), ConnectionId(1), Protocol::Http1);
    ex.request = Some(HttpRequest {
        method: "GET".into(),
        uri: "http://example.com/api".into(),
        headers: vec![("host".into(), "example.com".into())],
        is_connect: false,
    });
    ex.response_status = Some(200);
    ex.response_headers = vec![("content-type".into(), "application/json".into())];
    ex.response_content_type = Some("application/json".into());
    ex.request_body = Some(bytes::Bytes::new());
    ex.response_body = Some(bytes::Bytes::from_static(b"{\"ok\":true}"));

    let har = rproxy_export::to_har(&[ex]);
    let v: serde_json::Value = serde_json::from_str(&har).expect("valid JSON");
    let entries = v["log"]["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["request"]["method"], "GET");
    assert_eq!(entries[0]["request"]["url"], "http://example.com/api");
    assert_eq!(entries[0]["response"]["status"], 200);
    assert_eq!(entries[0]["response"]["content"]["text"], "{\"ok\":true}");
    assert!(v["log"]["creator"]["name"] == "rproxy");
}
