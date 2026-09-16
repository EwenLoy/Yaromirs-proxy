//! rproxy-core — ядро прокси-движка (tech-plan.md §3).
//! Ядро ничего не знает о UI: GUI и CLI — подписчики одной событийной шины.

pub mod events;
pub mod model;
pub mod net;
pub mod pipeline;

pub use events::{EventBus, ProxyEvent};
pub use model::{
    ConnectionId, Exchange, ExchangeCtx, ExchangeId, ExchangeState, HttpRequest, HttpResponse,
    Protocol, Timing,
};
pub use net::ProxyServer;
pub use pipeline::{
    InterceptAction, Pipeline, RequestInterceptor, ResponseInterceptor,
};
