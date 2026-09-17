//! Интеграционные тесты M0: forward proxy + CONNECT passthrough.
//! Запускаем локальный origin-сервер, затем прокси на эфемерных портах.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rproxy_core::{EventBus, ProxyEvent, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let body = format!("origin reply for {path}");
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from(body)))
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

async fn spawn_proxy() -> (String, tokio::sync::mpsc::UnboundedReceiver<ProxyEvent>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let bus = EventBus::new();
    let rx = {
        let mut sub = bus.subscribe();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(ev) => {
                        if tx.send(ev).is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(_) => continue,
                }
            }
        });
        rx
    };
    tokio::spawn(async move {
        let _ = ProxyServer::new(bus, rproxy_core::Pipeline::new())
            .serve(listener)
            .await;
    });
    (addr, rx)
}

/// Читает HTTP/1.1 ответ (заголовки + Content-Length тело) из сокета.
async fn read_http_response(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before headers complete");
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let (head, body_start) = buf.split_at(split + 4);
    let head = String::from_utf8_lossy(head).to_string();
    let mut body = body_start.to_vec();

    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before body complete");
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    (head, body)
}

#[tokio::test]
async fn forward_proxy_request_works() {
    let origin = spawn_origin().await;
    let (proxy, mut rx) = spawn_proxy().await;

    let mut stream = TcpStream::connect(&proxy).await.unwrap();
    // absolute-URI форма запроса к forward proxy
    let req = format!(
        "GET http://{origin}/hello HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let (head, body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    assert_eq!(&body[..], b"origin reply for /hello");

    // Ждём ExchangeCompleted.
    let mut completed = false;
    for _ in 0..100 {
        match rx.try_recv() {
            Ok(ProxyEvent::ExchangeCompleted(ex)) => {
                assert_eq!(ex.protocol, rproxy_core::Protocol::Http1);
                assert_eq!(ex.response_status, Some(200));
                assert_eq!(ex.state, rproxy_core::ExchangeState::Complete);
                // M2: тела захвачены
                assert_eq!(
                    ex.request_body.as_deref(),
                    Some(b"".as_slice())
                );
                assert_eq!(
                    ex.response_body.as_deref(),
                    Some(b"origin reply for /hello".as_slice())
                );
                completed = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert!(completed, "нет ExchangeCompleted события");
}

#[tokio::test]
async fn pipeline_short_circuit_intercepts_request() {
    use rproxy_core::model::{HttpRequest, HttpResponse};
    use rproxy_core::pipeline::{InterceptAction, Pipeline, RequestInterceptor};

    struct BlockAll;
    #[async_trait::async_trait]
    impl RequestInterceptor for BlockAll {
        async fn on_request(
            &self,
            _req: &mut HttpRequest,
            _ctx: &rproxy_core::ExchangeCtx,
        ) -> InterceptAction {
            InterceptAction::ShortCircuit(HttpResponse::text(403, "blocked by rproxy"))
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap().to_string();
    let bus = EventBus::new();
    let mut rx = {
        let mut sub = bus.subscribe();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(ev) = sub.recv().await {
                if tx.send(ev).is_err() {
                    break;
                }
            }
        });
        rx
    };
    let pipeline = Pipeline::new().with_request_interceptor(Box::new(BlockAll));
    let server = rproxy_core::ProxyServer::new(bus, pipeline);
    tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    let origin = spawn_origin().await;
    let mut stream = TcpStream::connect(&proxy_addr).await.unwrap();
    let req = format!(
        "GET http://{origin}/hello HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let (head, body) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 403"), "head: {head}");
    assert_eq!(&body[..], b"blocked by rproxy");

    let mut seen_blocked = false;
    for _ in 0..100 {
        match rx.try_recv() {
            Ok(ProxyEvent::ExchangeCompleted(ex)) => {
                if ex.state == rproxy_core::ExchangeState::Blocked {
                    seen_blocked = true;
                    break;
                }
            }
            Ok(_) => continue,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert!(seen_blocked, "нет Blocked-обмена");
}

#[tokio::test]
async fn connect_tunnel_passthrough_works() {

    // Plain origin (туннель протокол-агностичен: проверяем splice байтов).
    let origin = spawn_origin().await;
    let (proxy, _rx) = spawn_proxy().await;
    let mut stream = TcpStream::connect(&proxy).await.unwrap();
    let req = format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let (head, _) = read_http_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");

    // Говорим в туннель по HTTP/1.1 напрямую к origin.
    let get = format!("GET /tunnel HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n");
    stream.write_all(get.as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    let reply = String::from_utf8_lossy(&reply);
    assert!(reply.contains("origin reply for /tunnel"), "reply: {reply}");
}
