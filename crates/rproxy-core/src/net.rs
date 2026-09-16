//! Сетевой слой M0 (tech-plan.md §4):
//! - HTTP/1.1 forward proxy (запросы в absolute-URI форме),
//! - CONNECT tunnel passthrough (без MITM; MITM — этап M1).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{Either, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{ServerCertVerified, HandshakeSignatureValid};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig, SignatureScheme};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::events::{EventBus, ProxyEvent};
use crate::model::{
    ConnectionId, Exchange, ExchangeCtx, ExchangeId, ExchangeState, HttpRequest, Protocol,
};
use crate::pipeline::{InterceptAction, Pipeline};

type RespBody = Either<Incoming, Full<Bytes>>;
type HyperResponse = hyper::Response<RespBody>;
type ServiceResult = Result<HyperResponse, std::convert::Infallible>;

/// MITM-состояние: CA + кэш ServerConfig на хост + конфиг клиента к origin.
pub struct MitmState {
    ca: rproxy_cert::CertAuthority,
    servers: Mutex<HashMap<String, Option<Arc<ServerConfig>>>>,
    client_config: Arc<ClientConfig>,
}

impl MitmState {
    /// Загружает/создаёт CA (dir = None -> ~/.rproxy или RPROXY_CA_DIR).
    pub fn init() -> Result<Self, String> {
        let dir = rproxy_cert::default_ca_dir()
            .ok_or_else(|| "не найдена домашняя директория для хранения CA".to_string())?;
        let ca = rproxy_cert::CertAuthority::load_or_create(&dir)
            .map_err(|e| format!("CA init failed: {e}"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        eprintln!(
            "[rproxy] MITM включён. CA: {}",
            dir.join("ca.cert.pem").display()
        );
        Ok(Self {
            ca,
            servers: Mutex::new(HashMap::new()),
            client_config: Arc::new(client_config),
        })
    }

    /// PEM корневого сертификата (для экспорта/доверия).
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    fn server_config_for(&self, host: &str) -> Option<Arc<ServerConfig>> {
        let mut cache = self.servers.lock().unwrap();
        if let Some(cached) = cache.get(host) {
            return cached.clone();
        }
        let cfg = self.build_server_config(host).ok();
        cache.insert(host.to_string(), cfg.clone());
        cfg
    }

    fn build_server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let (chain, key_der) = self
            .ca
            .leaf_for(host)
            .map_err(|e| format!("leaf cert for {host}: {e}"))?;
        let key = PrivatePkcs8KeyDer::from(key_der);
        let cfg = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key.into())
        .map_err(|e| e.to_string())?;
        Ok(Arc::new(cfg))
    }
}

/// Опасный верификатор: принимаем любой сертификат origin-сервера (M1: debug proxy).
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// (проверка клиентских сертификатов не используется)

/// Состояние, доступное обработчикам соединений.
struct ProxyState {
    bus: EventBus,
    pipeline: Arc<Pipeline>,
    next_exchange_id: AtomicU64,
    next_connection_id: AtomicU64,
    mitm: Option<Arc<MitmState>>,
}

impl ProxyState {
    fn new_exchange_id(&self) -> ExchangeId {
        ExchangeId(self.next_exchange_id.fetch_add(1, Ordering::Relaxed))
    }
}

/// Forward HTTP proxy.
pub struct ProxyServer {
    bus: EventBus,
    pipeline: Arc<Pipeline>,
    mitm: Option<Arc<MitmState>>,
}

impl Default for ProxyServer {
    fn default() -> Self {
        Self::new(EventBus::default(), Pipeline::new())
    }
}

impl ProxyServer {
    pub fn new(bus: EventBus, pipeline: Pipeline) -> Self {
        Self {
            bus,
            pipeline: Arc::new(pipeline),
            mitm: None,
        }
    }

    /// Включить MITM-перехват HTTPS (загрузка/генерация CA).
    pub fn with_mitm(mut self) -> Self {
        match MitmState::init() {
            Ok(m) => self.mitm = Some(Arc::new(m)),
            Err(e) => eprintln!("[rproxy] MITM недоступен, продолжаем passthrough: {e}"),
        }
        self
    }

    /// Публичный доступ к шине для подписчиков (CLI/GUI/экспортёры).
    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    /// Запуск сервера: bind + accept-loop (бесконечный).
    pub async fn run(self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve(listener).await
    }

    /// Serve на уже созданном listener (удобно для тестов с эфемерным портом).
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let state = Arc::new(ProxyState {
            bus: self.bus,
            pipeline: self.pipeline,
            next_exchange_id: AtomicU64::new(1),
            next_connection_id: AtomicU64::new(1),
            mitm: self.mitm,
        });

        loop {
            let (stream, _peer) = listener.accept().await?;
            let state = state.clone();
            tokio::spawn(async move {
                let conn_id =
                    ConnectionId(state.next_connection_id.fetch_add(1, Ordering::Relaxed));
                state.bus.publish(ProxyEvent::ConnectionOpened(conn_id));
                let _ = serve_connection(stream, state.clone(), conn_id).await;
                state.bus.publish(ProxyEvent::ConnectionClosed(conn_id));
            });
        }
    }
}

async fn serve_connection(
    stream: TcpStream,
    state: Arc<ProxyState>,
    conn_id: ConnectionId,
) -> Result<(), hyper::Error> {
    let service = service_fn(move |req| {
        let state = state.clone();
        async move {
            if req.method() == hyper::Method::CONNECT {
                handle_connect(req, state, conn_id).await
            } else {
                handle_forward(req, state, conn_id).await
            }
        }
    });
    http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
}

fn empty_response(status: u16) -> HyperResponse {
    hyper::Response::builder()
        .status(status)
        .body(Either::Right(Full::new(Bytes::new())))
        .unwrap()
}

fn finish_exchange(state: &ProxyState, mut exchange: Exchange, state_: ExchangeState) {
    exchange.state = state_;
    exchange.timing.completed_at = Some(Instant::now());
    state.bus.publish(ProxyEvent::ExchangeCompleted(exchange));
}

// ---------------- CONNECT tunnel passthrough ----------------

async fn handle_connect(
    req: hyper::Request<Incoming>,
    state: Arc<ProxyState>,
    conn_id: ConnectionId,
) -> ServiceResult {
    // MITM-ветка: расшифровываем HTTPS, если включён.
    if let Some(mitm) = state.mitm.clone() {
        return handle_connect_mitm(req, state, conn_id, mitm).await;
    }
    // Passthrough-ветка (M0): туннель без расшифровки.
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .unwrap_or("")
        .to_string();

    let exchange_id = state.new_exchange_id();
    let mut exchange = Exchange::new(exchange_id, conn_id, Protocol::ConnectTunnel);
    exchange.request = Some(HttpRequest {
        method: "CONNECT".into(),
        uri: authority.clone(),
        headers: Vec::new(),
        is_connect: true,
    });
    state.bus.publish(ProxyEvent::ExchangeStarted(exchange.clone()));

    let remote = match TcpStream::connect(&authority).await {
        Ok(s) => s,
        Err(e) => {
            exchange.error = Some(format!("connect: {e}"));
            finish_exchange(&state, exchange, ExchangeState::Failed);
            return Ok(empty_response(502));
        }
    };

    let upgrade_fut = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match upgrade_fut.await {
            Ok(upgraded) => {
                // Даункастим к tokio TcpStream (прокси сам инициировал upgrade
                // над чистым TcpStream), чтобы использовать copy_bidirectional.
                let mut client_io = match upgraded.downcast::<TokioIo<TcpStream>>() {
                    Ok(parts) => {
                        let (io, read_buf) = (parts.io, parts.read_buf);
                        let mut io = io.into_inner();
                        // hyper мог забуферизовать начало потока — отдаём его в туннель.
                        if !read_buf.is_empty() {
                            let _ = io.write_all(&read_buf).await;
                        }
                        io
                    }
                    Err(_) => {
                        exchange.error = Some("upgrade downcast failed".into());
                        finish_exchange(&state, exchange, ExchangeState::Failed);
                        return;
                    }
                };
                let mut remote_io = remote;
                let res = tokio::io::copy_bidirectional(&mut client_io, &mut remote_io).await;
                match res {
                    Ok(_) => finish_exchange(&state, exchange, ExchangeState::Complete),
                    Err(e) => {
                        exchange.error = Some(format!("tunnel: {e}"));
                        finish_exchange(&state, exchange, ExchangeState::Failed);
                    }
                }
            }
            Err(e) => {
                exchange.error = Some(format!("upgrade: {e}"));
                finish_exchange(&state, exchange, ExchangeState::Failed);
            }
        }
    });

    Ok(empty_response(200))
}

// ---------------- HTTP/1.1 forward proxy ----------------

async fn handle_forward(
    req: hyper::Request<Incoming>,
    state: Arc<ProxyState>,
    conn_id: ConnectionId,
) -> ServiceResult {
    let exchange_id = state.new_exchange_id();
    let mut exchange = Exchange::new(exchange_id, conn_id, Protocol::Http1);
    exchange.request = Some(HttpRequest {
        method: req.method().as_str().into(),
        uri: req.uri().to_string(),
        headers: req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.to_str().unwrap_or("").into()))
            .collect(),
        is_connect: false,
    });
    state.bus.publish(ProxyEvent::ExchangeStarted(exchange.clone()));

    // Прогон через pipeline (M0: пустой по умолчанию; тулы подключаются сюда).
    let ctx = ExchangeCtx {
        exchange_id: exchange_id.0,
    };
    let mut model_req = exchange.request.clone().unwrap();
    let action = state.pipeline.process_request(&mut model_req, &ctx).await;
    match action {
        InterceptAction::ShortCircuit(resp) => {
            let status = resp.status;
            let mut builder = hyper::Response::builder().status(status);
            for (k, v) in &resp.headers {
                builder = builder.header(k, v);
            }
            let response = builder.body(Either::Right(Full::new(resp.body))).unwrap();
            finish_exchange(&state, exchange, ExchangeState::Blocked);
            return Ok(response);
        }
        InterceptAction::Block { status } => {
            finish_exchange(&state, exchange, ExchangeState::Blocked);
            return Ok(empty_response(status));
        }
        InterceptAction::Hold => {
            // Breakpoints — этап M6; пока трактуем как continue.
        }
        InterceptAction::Continue => {}
    }

    // Форвардинг: absolute-URI сохраняется; коннектор резолвит host из URI.
    let client: Client<HttpConnector, Incoming> =
        Client::builder(TokioExecutor::new()).build_http();

    let result = client.request(req).await;

    match result {
        Ok(resp) => {
            exchange.response_status = Some(resp.status().as_u16());
            let (parts, body) = resp.into_parts();
            // Тело отдаём потоково, без буферизации.
            let response = http::Response::from_parts(parts, Either::Left(body));
            finish_exchange(&state, exchange, ExchangeState::Complete);
            Ok(response)
        }
        Err(e) => {
            exchange.error = Some(e.to_string());
            finish_exchange(&state, exchange, ExchangeState::Failed);
            Ok(empty_response(502))
        }
    }
}


// ---------------- MITM: расшифровка HTTPS ----------------

async fn handle_connect_mitm(
    req: hyper::Request<Incoming>,
    state: Arc<ProxyState>,
    conn_id: ConnectionId,
    mitm: Arc<MitmState>,
) -> ServiceResult {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .unwrap_or("")
        .to_string();

    let exchange_id = state.new_exchange_id();
    let mut exchange = Exchange::new(exchange_id, conn_id, Protocol::ConnectTunnel);
    exchange.request = Some(HttpRequest {
        method: "CONNECT".into(),
        uri: authority.clone(),
        headers: Vec::new(),
        is_connect: true,
    });
    state.bus.publish(ProxyEvent::ExchangeStarted(exchange.clone()));

    let upgrade_fut = hyper::upgrade::on(req);

    tokio::spawn(async move {
        let client_tcp = match upgrade_fut.await {
            Ok(up) => match up.downcast::<TokioIo<TcpStream>>() {
                Ok(parts) => parts.io.into_inner(),
                Err(_) => {
                    exchange.error = Some("upgrade downcast failed".into());
                    finish_exchange(&state, exchange, ExchangeState::Failed);
                    return;
                }
            },
            Err(e) => {
                exchange.error = Some(format!("upgrade: {e}"));
                finish_exchange(&state, exchange, ExchangeState::Failed);
                return;
            }
        };

        let Some(server_cfg) = mitm.server_config_for(&authority) else {
            exchange.error = Some(format!("leaf cert for {authority} failed"));
            finish_exchange(&state, exchange, ExchangeState::Failed);
            return;
        };

        let acceptor = TlsAcceptor::from(server_cfg);
        let tls_stream = match acceptor.accept(client_tcp).await {
            Ok(s) => s,
            Err(e) => {
                exchange.error = Some(format!("client TLS handshake ({authority}): {e}"));
                finish_exchange(&state, exchange, ExchangeState::Failed);
                return;
            }
        };

        // Обслуживаем HTTP/1.1 поверх расшифрованного TLS (с keep-alive).
        let (state_svc, mitm_svc, authority_svc) = (state.clone(), mitm.clone(), authority.clone());
        let service = service_fn(move |req| {
            let state = state_svc.clone();
            let mitm = mitm_svc.clone();
            let authority = authority_svc.clone();
            async move { forward_https_decrypted(req, state, conn_id, authority, mitm).await }
        });
        let served = http1::Builder::new()
            .keep_alive(true)
            .serve_connection(TokioIo::new(tls_stream), service)
            .await;
        match served {
            Ok(()) => finish_exchange(&state, exchange, ExchangeState::Complete),
            Err(e) => {
                exchange.error = Some(format!("mitm session ({authority}): {e}"));
                finish_exchange(&state, exchange, ExchangeState::Failed);
            }
        }
    });

    Ok(empty_response(200))
}


/// Один расшифрованный запрос: TLS к origin, обмен, событие в шину.
async fn forward_https_decrypted(
    req: hyper::Request<Incoming>,
    state: Arc<ProxyState>,
    conn_id: ConnectionId,
    authority: String,
    mitm: Arc<MitmState>,
) -> ServiceResult {
    let exchange_id = state.new_exchange_id();
    let mut exchange = Exchange::new(exchange_id, conn_id, Protocol::Http1);

    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let uri_display = format!("https://{authority}{path}");

    exchange.request = Some(HttpRequest {
        method: req.method().as_str().into(),
        uri: uri_display,
        headers: req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.to_str().unwrap_or("").into()))
            .collect(),
        is_connect: false,
    });
    state.bus.publish(ProxyEvent::ExchangeStarted(exchange.clone()));

    // Pipeline (тулы), как и для plain HTTP.
    let ctx = ExchangeCtx {
        exchange_id: exchange_id.0,
    };
    let mut model_req = exchange.request.clone().unwrap();
    let action = state.pipeline.process_request(&mut model_req, &ctx).await;
    if let InterceptAction::Block { status } = action {
        finish_exchange(&state, exchange, ExchangeState::Blocked);
        return Ok(empty_response(status));
    }

    // Origin: host:port из authority (порт по умолчанию 443).
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(443u16)),
        None => (authority.clone(), 443u16),
    };

    let connector = TlsConnector::from(mitm.client_config.clone());
    let tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(t) => t,
        Err(e) => {
            exchange.error = Some(format!("origin connect: {e}"));
            finish_exchange(&state, exchange, ExchangeState::Failed);
            return Ok(empty_response(502));
        }
    };
    let server_name = match ServerName::try_from(host.clone()) {
        Ok(n) => n,
        Err(e) => {
            exchange.error = Some(format!("bad server name: {e}"));
            finish_exchange(&state, exchange, ExchangeState::Failed);
            return Ok(empty_response(502));
        }
    };
    let tls = match connector.connect(server_name, tcp).await {
        Ok(t) => t,
        Err(e) => {
            exchange.error = Some(format!("origin TLS handshake: {e}"));
            finish_exchange(&state, exchange, ExchangeState::Failed);
            return Ok(empty_response(502));
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(tls)).await {
        Ok(x) => x,
        Err(e) => {
            exchange.error = Some(format!("origin http1 handshake: {e}"));
            finish_exchange(&state, exchange, ExchangeState::Failed);
            return Ok(empty_response(502));
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // origin-form запрос: path-only URI + Host.
    let (mut parts, body) = req.into_parts();
    parts.uri = path.parse::<http::Uri>().expect("valid path_and_query");
    if let Ok(host_hdr) = http::HeaderValue::from_str(&authority) {
        parts.headers.insert(http::header::HOST, host_hdr);
    }
    parts.headers.remove("proxy-connection");
    parts.headers.remove("proxy-authorization");
    let outgoing = http::Request::from_parts(parts, body);

    let result = sender.send_request(outgoing).await;

    match result {
        Ok(resp) => {
            exchange.response_status = Some(resp.status().as_u16());
            let (parts, body) = resp.into_parts();
            let response = http::Response::from_parts(parts, Either::Left(body));
            finish_exchange(&state, exchange, ExchangeState::Complete);
            Ok(response)
        }
        Err(e) => {
            exchange.error = Some(e.to_string());
            finish_exchange(&state, exchange, ExchangeState::Failed);
            Ok(empty_response(502))
        }
    }
}


