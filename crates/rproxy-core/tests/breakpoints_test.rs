//! E2E: breakpoints — удержание запроса, решение оператора Continue/Drop.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rproxy_core::{BreakpointDecision, BreakpointHub, EventBus, ProxyEvent, ProxyServer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
                            .body(Full::new(Bytes::from("held origin body")))
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

/// Сделать запрос через прокси, вернуть статус-строку ответа.
async fn request_via_proxy(proxy: String, origin: String) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let req = format!("GET http://{origin}/bp HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string()
}

async fn spawn_proxy(hub: Arc<BreakpointHub>) -> (String, tokio::sync::mpsc::UnboundedReceiver<ProxyEvent>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let bus = EventBus::new();
    let rx = {
        let mut sub = bus.subscribe();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(ev) = sub.recv().await {
                if tx.send(ev).is_err() { break; }
            }
        });
        rx
    };
    tokio::spawn(async move {
        let _ = ProxyServer::new(bus, rproxy_core::Pipeline::new())
            .with_breakpoints_hub(hub)
            .serve(listener)
            .await;
    });
    (addr, rx)
}

#[tokio::test]
async fn breakpoint_continue_releases_request() {
    let origin = spawn_origin().await;
    let hub = Arc::new(BreakpointHub::new("/bp", true));
    let (proxy, mut rx) = spawn_proxy(hub.clone()).await;

    let task = tokio::spawn(request_via_proxy(proxy.clone(), origin.clone()));

    // Ждём BreakpointHit.
    let mut hit = false;
    for _ in 0..100 {
        match rx.try_recv() {
            Ok(ProxyEvent::BreakpointHit(ex)) => {
                assert!(ex.request.as_ref().unwrap().uri.contains("/bp"));
                hit = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert!(hit, "нет BreakpointHit");

    // Оператор: Continue.
    assert!(hub.resolve(hub.pending()[0], BreakpointDecision::Continue));
    let head = task.await.unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
}

#[tokio::test]
async fn breakpoint_drop_returns_403() {
    let origin = spawn_origin().await;
    let hub = Arc::new(BreakpointHub::new("/bp", true));
    let (proxy, mut rx) = spawn_proxy(hub.clone()).await;

    let task = tokio::spawn(request_via_proxy(proxy.clone(), origin.clone()));

    let mut hit = false;
    for _ in 0..100 {
        match rx.try_recv() {
            Ok(ProxyEvent::BreakpointHit(_)) => { hit = true; break; }
            Ok(_) => continue,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert!(hit, "нет BreakpointHit");

    hub.resolve_all(BreakpointDecision::Drop);
    let head = task.await.unwrap();
    assert!(head.starts_with("HTTP/1.1 403"), "head: {head}");
}

#[tokio::test]
async fn disabled_hub_passes_through() {
    let origin = spawn_origin().await;
    let hub = Arc::new(BreakpointHub::new("held", false));
    let (proxy, _rx) = spawn_proxy(hub).await;
    let head = request_via_proxy(proxy, origin).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
}
