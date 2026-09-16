//! Событийная шина (tech-plan.md §3.4).
//! `tokio::sync::broadcast` — GUI/CLI/экспортёры подписываются на ProxyEvent.

use crate::model::{ConnectionId, Exchange, ExchangeId};
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum ProxyEvent {
    ExchangeStarted(Exchange),
    ExchangeUpdated(Exchange),
    ExchangeCompleted(Exchange),
    ConnectionOpened(ConnectionId),
    ConnectionClosed(ConnectionId),
    BreakpointHit(ExchangeId),
    Error(String),
}

/// Broadcast-шина событий прокси-движка.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<ProxyEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1024);
        Self { sender }
    }

    /// Подписка на поток событий (каждый подписчик получает свою копию).
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.sender.subscribe()
    }

    /// Публикация события. Не паникует, если подписчиков нет.
    pub fn publish(&self, event: ProxyEvent) {
        let _ = self.sender.send(event);
    }
}
