//! Сетевой слой M0 (tech-plan.md §4):
//! - HTTP/1.1 forward proxy (запросы в absolute-URI форме),
//! - CONNECT tunnel passthrough (без MITM; MITM — этап M1).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{Either, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::events::{EventBus, ProxyEvent};
use crate::model::{
    ConnectionId, Exchange, ExchangeCtx, ExchangeId, ExchangeState, HttpRequest, Protocol,
};
use crate::pipeline::{InterceptAction, Pipeline};

type RespBody = Either<Incoming, Full<Bytes>>;
type HyperResponse = hyper::Response<RespBody>;
type ServiceResult = Result<HyperResponse, std::convert::Infallible>;

/// Состояние, доступное обработчикам соединений.
struct ProxyState {
    bus: EventBus,
    pipeline: Arc<Pipeline>,
    next_exchange_id: AtomicU64,
    next_connection_id: AtomicU64,
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
        }
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

