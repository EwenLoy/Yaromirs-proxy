//! Интеграционный тест MITM: CONNECT -> TLS-терминация -> расшифрованный HTTP до origin.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::CertifiedKey;
use rproxy_core::{EventBus, ProxyEvent, ProxyServer};
use rustls::client::danger::{ServerCertVerified, HandshakeSignatureValid};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ---------- Origin: TLS HTTP/1.1 сервер ----------

async fn spawn_tls_origin() -> String {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["origin.test".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], key.into())
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else { return };
                let service = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from("secret from tls origin")))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    addr
}

// ---------- Клиентский TLS-верификатор: принимаем leaf от rproxy CA ----------

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ED25519]
    }
}



#[tokio::test]
async fn mitm_decrypts_https_traffic() {
    // CA в отдельной временной папке на время теста.
    let temp = std::env::temp_dir().join(format!("rproxy-test-ca-{}", std::process::id()));
    std::env::set_var("RPROXY_CA_DIR", &temp);

    let origin = spawn_tls_origin().await;

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
    let server = ProxyServer::new(bus, rproxy_core::Pipeline::new()).with_mitm();
    tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });


    // CONNECT до прокси
    let mut stream = TcpStream::connect(&proxy_addr).await.unwrap();
    let req = format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut head = [0u8; 512];
    let n = stream.read(&mut head).await.unwrap();
    let head = String::from_utf8_lossy(&head[..n]);
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");

    // TLS к прокси (он представится leaf-сертификатом нашего CA)
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let mut tls = connector
        .connect(ServerName::try_from("origin.test").unwrap(), stream)
        .await
        .expect("mitm TLS handshake");

    // Расшифрованный HTTP-запрос через MITM
    tls.write_all(b"GET /sec HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut reply = Vec::new();
    tls.read_to_end(&mut reply).await.unwrap();
    let reply = String::from_utf8_lossy(&reply);
    assert!(
        reply.contains("secret from tls origin"),
        "расшифрованный ответ не получен: {reply}"
    );

    // Событие содержит https:// URI и статус origin
    let mut seen = None;
    for _ in 0..100 {
        match rx.try_recv() {
            Ok(ProxyEvent::ExchangeCompleted(ex)) => {
                if let Some(req) = &ex.request {
                    if req.uri.ends_with("/sec") {
                        seen = Some(ex.response_status);
                        break;
                    }
                }
            }
            Ok(_) => continue,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert_eq!(seen, Some(Some(200)), "нет события о расшифрованном обмене");

    let _ = std::fs::remove_dir_all(&temp);
}
