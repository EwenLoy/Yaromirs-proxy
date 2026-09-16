//! Pipeline (tech-plan.md §3.3): цепочка interceptors — прямой аналог тулов Charles.
//! Каждый тул (Map Local, Block List, Rewrite, ...) реализует RequestInterceptor/ResponseInterceptor
//! и применяется по порядку. Порядок конфигурируется явно.

use crate::model::{ExchangeCtx, HttpRequest, HttpResponse};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub enum InterceptAction {
    Continue,
    Block { status: u16 },
    Hold,
    /// Map Local / Block List — немедленный ответ без обращения к origin.
    ShortCircuit(HttpResponse),
}

#[async_trait]
pub trait RequestInterceptor: Send + Sync {
    async fn on_request(&self, req: &mut HttpRequest, ctx: &ExchangeCtx) -> InterceptAction;
}

#[async_trait]
pub trait ResponseInterceptor: Send + Sync {
    async fn on_response(&self, resp: &mut HttpResponse, ctx: &ExchangeCtx) -> InterceptAction;
}

/// Упорядоченный набор interceptors.
#[derive(Default)]
pub struct Pipeline {
    request_interceptors: Vec<Box<dyn RequestInterceptor>>,
    response_interceptors: Vec<Box<dyn ResponseInterceptor>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_request_interceptor(mut self, i: Box<dyn RequestInterceptor>) -> Self {
        self.request_interceptors.push(i);
        self
    }

    pub fn with_response_interceptor(mut self, i: Box<dyn ResponseInterceptor>) -> Self {
        self.response_interceptors.push(i);
        self
    }

    /// Прогон запроса через цепочку. Возвращает итоговое действие.
    pub async fn process_request(
        &self,
        req: &mut HttpRequest,
        ctx: &ExchangeCtx,
    ) -> InterceptAction {
        for interceptor in &self.request_interceptors {
            match interceptor.on_request(req, ctx).await {
                InterceptAction::Continue => {}
                action => return action,
            }
        }
        InterceptAction::Continue
    }

    /// Прогон ответа через цепочку.
    pub async fn process_response(
        &self,
        resp: &mut HttpResponse,
        ctx: &ExchangeCtx,
    ) -> InterceptAction {
        for interceptor in &self.response_interceptors {
            match interceptor.on_response(resp, ctx).await {
                InterceptAction::Continue => {}
                action => return action,
            }
        }
        InterceptAction::Continue
    }
}
