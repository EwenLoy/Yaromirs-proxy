//! Breakpoints (M6): удержание запроса до решения оператора.
//! Хаб разделяется между движком и UI (GUI/CLI/MCP): при срабатывании
//! публикуется ProxyEvent::BreakpointHit, соединение ждёт Continue/Drop.

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BreakpointDecision {
    Continue,
    Drop,
}

struct BpState {
    enabled: bool,
    pattern: String,
    pending: HashMap<u64, oneshot::Sender<BreakpointDecision>>,
}

impl Default for BpState {
    fn default() -> Self {
        Self { enabled: false, pattern: String::new(), pending: HashMap::new() }
    }
}

#[derive(Default)]
pub struct BreakpointHub {
    state: Mutex<BpState>,
}

impl BreakpointHub {
    pub fn new(pattern: &str, enabled: bool) -> Self {
        Self {
            state: Mutex::new(BpState {
                enabled,
                pattern: pattern.to_string(),
                pending: HashMap::new(),
            }),
        }
    }

    pub fn set_enabled(&self, on: bool) {
        self.state.lock().unwrap().enabled = on;
    }

    pub fn enabled(&self) -> bool {
        self.state.lock().unwrap().enabled
    }

    pub fn set_pattern(&self, pattern: impl Into<String>) {
        self.state.lock().unwrap().pattern = pattern.into();
    }

    pub fn pattern(&self) -> String {
        self.state.lock().unwrap().pattern.clone()
    }

    /// Должен ли этот URI застрять в breakpoint.
    pub fn should_hold(&self, uri: &str) -> bool {
        let st = self.state.lock().unwrap();
        st.enabled && !st.pattern.is_empty() && uri.contains(&st.pattern)
    }

    pub fn register(&self, id: u64, tx: oneshot::Sender<BreakpointDecision>) {
        self.state.lock().unwrap().pending.insert(id, tx);
    }

    /// Вернуть true, если решение доставлено.
    pub fn resolve(&self, id: u64, decision: BreakpointDecision) -> bool {
        let tx = self.state.lock().unwrap().pending.remove(&id);
        match tx {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }

    /// Индексы застрявших запросов.
    pub fn pending(&self) -> Vec<u64> {
        self.state.lock().unwrap().pending.keys().copied().collect()
    }

    /// Применить решение ко всем застрявшим; вернуть количество.
    pub fn resolve_all(&self, decision: BreakpointDecision) -> usize {
        let mut st = self.state.lock().unwrap();
        let n = st.pending.len();
        for (_, tx) in st.pending.drain() {
            let _ = tx.send(decision);
        }
        n
    }
}
