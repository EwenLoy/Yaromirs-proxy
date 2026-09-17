//! Тесты M3-тулов: TOML-конфиг + поведение interceptors + e2e через прокси.

use rproxy_core::tools::{load_pipeline, MapLocalRule, Rule, ToolsConfig};
use rproxy_core::{EventBus, HttpRequest, ProxyEvent, ProxyServer};
use tokio::net::{TcpListener, TcpStream};

fn req(uri: &str, headers: &[(&str, &str)]) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        uri: uri.into(),
        headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        is_connect: false,
    }
}

#[tokio::test]
async fn block_and_map_local_and_map_remote() {
    // Map Local через временный файл.
    let tmp = std::env::temp_dir().join("rproxy-mock.json");
    std::fs::write(&tmp, b"{\"mocked\":true}").unwrap();

    let cfg = ToolsConfig {
        block: vec![Rule { pattern: "ads.example.com".into(), status: Some(418), replace: None }],
        no_caching: false,
        block_cookies: false,
        map_local: vec![MapLocalRule {
            pattern: "api.test/config".into(),
            file: tmp.to_string_lossy().to_string(),
            status: None,
            content_type: None,
        }],
        map_remote: vec![Rule {
            pattern: "api.old.com".into(),
            status: None,
            replace: Some("api.new.com".into()),
        }],
    };
    let pipeline = rproxy_core::tools::build_pipeline(&cfg);
    let ctx = rproxy_core::ExchangeCtx { exchange_id: 1 };

    // Block
    let mut r = req("http://ads.example.com/x", &[]);
    match pipeline.process_request(&mut r, &ctx).await {
        rproxy_core::InterceptAction::ShortCircuit(resp) => assert_eq!(resp.status, 418),
        other => panic!("expected ShortCircuit, got {other:?}"),
    }

    // Map Local
    let mut r = req("https://api.test/config", &[]);
    match pipeline.process_request(&mut r, &ctx).await {
        rproxy_core::InterceptAction::ShortCircuit(resp) => {
            assert_eq!(resp.body.as_ref(), b"{\"mocked\":true}".as_slice());
            assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v.contains("json")));
        }
        other => panic!("expected ShortCircuit, got {other:?}"),
    }

    // Map Remote: uri + host header переписаны
    let mut r = req("https://api.old.com/v1", &[("host", "api.old.com")]);
    assert!(matches!(
        pipeline.process_request(&mut r, &ctx).await,
        rproxy_core::InterceptAction::Continue
    ));
    assert!(r.uri.contains("api.new.com"));
    assert!(r.headers.iter().any(|(k, v)| k == "host" && v == "api.new.com"));

    // Map Local не срабатывает на других URL (continue)
    let mut r = req("https://other.test/", &[]);
    assert!(matches!(
        pipeline.process_request(&mut r, &ctx).await,
        rproxy_core::InterceptAction::Continue
    ));

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn toml_config_parses() {
    let dir = std::env::temp_dir().join("rproxy-tools-test.toml");
    std::fs::write(&dir, rproxy_core::tools::example_toml()).unwrap();
    let p = load_pipeline(&dir).expect("valid config");
    let _ = p; // pipeline собрался
    let _ = std::fs::remove_file(&dir);
}

/// E2E: block через реальный прокси — origin не вызывается, клиент получает 403.
#[tokio::test]
async fn block_tool_e2e() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap().to_string();
    let bus = EventBus::new();
    let mut rx = {
        let mut sub = bus.subscribe();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(ev) = sub.recv().await {
                if tx.send(ev).is_err() { break; }
            }
        });
        rx
    };
    let cfg = ToolsConfig {
        block: vec![Rule { pattern: "blocked.test".into(), status: Some(403), replace: None }],
        ..Default::default()
    };
    let server = ProxyServer::new(bus, rproxy_core::tools::build_pipeline(&cfg));
    tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    let mut stream = TcpStream::connect(&proxy_addr).await.unwrap();
    let req = "GET http://blocked.test/x HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n";
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf);
    assert!(head.starts_with("HTTP/1.1 403"), "head: {head}");
    assert!(head.contains("blocked by rproxy"));

    // событие Blocked
    let mut blocked = false;
    for _ in 0..50 {
        match rx.try_recv() {
            Ok(ProxyEvent::ExchangeCompleted(ex)) => {
                if ex.state == rproxy_core::ExchangeState::Blocked { blocked = true; break; }
            }
            Ok(_) => continue,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert!(blocked, "нет Blocked-обмена");
}
