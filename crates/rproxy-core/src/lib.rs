//! rproxy-core — ядро прокси-движка (tech-plan.md §3).
//! Ядро ничего не знает о UI: GUI и CLI — подписчики одной событийной шины.

pub mod breakpoints;
pub mod events;
pub mod model;
pub mod net;
pub mod pipeline;
pub mod pretty;
pub mod ssl_proxy;
pub mod tools;

pub use breakpoints::{BreakpointDecision, BreakpointHub};

pub use events::{EventBus, ProxyEvent};
pub use model::{
    ConnectionId, Exchange, ExchangeCtx, ExchangeId, ExchangeState, HttpRequest, HttpResponse,
    Protocol, Timing,
};
pub use net::ProxyServer;
pub use pipeline::{
    InterceptAction, Pipeline, RequestInterceptor, ResponseInterceptor,
};
pub use ssl_proxy::{pattern_matches, SslProxyConfig};
