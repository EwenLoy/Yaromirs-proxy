//! E2E: трафик через прокси попадает в MCP-сессию и виден агенту.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rproxy_core::{EventBus, ProxyServer};
use rproxy_mcp::Store;
use serde_json::json;
use tokio::net::TcpListener;

async fn spawn_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let service = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from("mcp e2e body")))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn traffic_visible_via_mcp_tools() {
    let origin = spawn_origin().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap().to_string();
    let bus = EventBus::new();
    let store = Store::new();
    let store2 = store.clone();

    tokio::spawn(async move {
        let collector = bus.clone();
        tokio::spawn(async move {
            let mut sub = collector.subscribe();
            while let Ok(ev) = sub.recv().await {
                if let rproxy_core::ProxyEvent::ExchangeCompleted(ex) = ev {
                    store2.session.lock().unwrap().push(ex);
                }
            }
        });
        let _ = ProxyServer::new(bus, rproxy_core::Pipeline::new())
            .serve(listener)
            .await;
    });

    // Запрос через прокси.
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr).await.unwrap();
    let req = format!("GET http://{origin}/mcp HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf).contains("mcp e2e body"));

    // Небольшая задержка на доставку события.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Агент спрашивает список flows.
    let flows = rproxy_mcp_call(&store, "get_flows", json!({})).await;
    let text = flows["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("http"), "flows должен содержать запрос: {text}");
    let flow = rproxy_mcp_call(&store, "get_flow", json!({"index": 0})).await;
    let text = flow["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("mcp e2e body"), "тело должно быть видно агенту: {text}");
    let curl = rproxy_mcp_call(&store, "export_flow_curl", json!({"index": 0})).await;
    assert!(curl["content"][0]["text"].as_str().unwrap().starts_with("curl -X GET"));
}

// Обёртка: call_tool приватная, дергаем через публичный API был бы вариант, но для теста
// дублируем минимальный вызов через serve невозможно — поэтому здесь локальная копия логики.
async fn rproxy_mcp_call(store: &Store, name: &str, args: serde_json::Value) -> serde_json::Value {
    // rproxy_mcp::call_tool экспортирован для тестов (см. lib.rs #[doc(hidden)]).
    rproxy_mcp::call_tool(store, name, args).await
}
