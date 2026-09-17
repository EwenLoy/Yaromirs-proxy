//! Модель данных прокси-движка (rproxy-core::model).
//! См. tech-plan.md §3.2.

use std::time::{Duration, Instant};

/// Идентификатор обмена (запрос + ответ).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExchangeId(pub u64);

/// Идентификатор клиентского соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u64);

/// Протокол обмена. M0: Http1 + ConnectTunnel (passthrough).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
    WebSocket,
    Socks5,
    ConnectTunnel,
    RawTcp,
}

/// Состояние обмена в пайплайне/хранилище.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeState {
    InProgress,
    Complete,
    Failed,
    Blocked,
    BreakpointHeld,
}

/// Контекст обмена (пока минимальный; расширится в M1+ — TLS info, connection и т.д.).
#[derive(Debug, Clone)]
pub struct ExchangeCtx {
    pub exchange_id: u64,
}

/// Легковесное описание входящего запроса (без тела — для M0).
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    /// Абсолютный URI (для forward proxy) или origin-form (для CONNECT — host:port).
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub is_connect: bool,
}

/// Легковесное описание ответа для ShortCircuit/Block.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
}

impl HttpResponse {
    pub fn text(status: u16, body: impl Into<bytes::Bytes>) -> Self {
        Self {
            status,
            reason: None,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: body.into(),
        }
    }
}

/// Тайминги обмена (M0: общий elapsed; DNS/Connect/TLS появятся в M1+).
#[derive(Debug, Clone, Copy, Default)]
pub struct Timing {
    pub started_at: Option<Instant>,
    pub completed_at: Option<Instant>,
}

impl Timing {
    pub fn start() -> Self {
        Self {
            started_at: Some(Instant::now()),
            completed_at: None,
        }
    }

    pub fn total(&self) -> Option<Duration> {
        match (self.started_at, self.completed_at) {
            (Some(s), Some(c)) => Some(c - s),
            _ => None,
        }
    }
}

/// Exchange — единица трафика в журнале (аналог row в Sequence view).
#[derive(Debug, Clone)]
pub struct Exchange {
    pub id: ExchangeId,
    pub connection_id: ConnectionId,
    pub protocol: Protocol,
    pub state: ExchangeState,
    pub request: Option<HttpRequest>,
    pub response_status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_content_type: Option<String>,
    pub request_body: Option<bytes::Bytes>,
    pub response_body: Option<bytes::Bytes>,
    /// Расшифрованное (gzip/deflate) тело ответа, если применимо.
    pub response_body_decoded: Option<bytes::Bytes>,
    pub timing: Timing,
    pub started_wall: Option<std::time::SystemTime>,
    pub error: Option<String>,
}

impl Exchange {
    pub fn new(id: ExchangeId, connection_id: ConnectionId, protocol: Protocol) -> Self {
        Self {
            id,
            connection_id,
            protocol,
            state: ExchangeState::InProgress,
            request: None,
            response_status: None,
            response_headers: Vec::new(),
            response_content_type: None,
            request_body: None,
            response_body: None,
            response_body_decoded: None,
            timing: Timing::start(),
            started_wall: Some(std::time::SystemTime::now()),
            error: None,
        }
    }
}

/// Лимит буферизации тела (байты) — сверх этого тело не сохраняется.
pub const BODY_CAPTURE_LIMIT: usize = 16 * 1024 * 1024;

