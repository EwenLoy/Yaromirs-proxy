//! SSL-proxying locations в стиле Charles (tech-plan.md §12.2).
//! Паттерны вида `*`, `*:*`, `*.example.com:*`, `host`, `host:port`.
//! Конфиг shared между GUI и движком через `Arc<RwLock<..>>` — хот-релоад без рестарта.

/// Конфиг SSL-proxying: какие хосты расшифровывать (MITM), какие — туннелем.
#[derive(Debug, Clone)]
pub struct SslProxyConfig {
    pub enabled: bool,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Default for SslProxyConfig {
    fn default() -> Self {
        Self { enabled: true, include: vec!["*:*".to_string()], exclude: Vec::new() }
    }
}

impl SslProxyConfig {
    /// Расшифровывать ли CONNECT host:port (MITM) или пустить туннелем.
    pub fn should_mitm(&self, host: &str, port: u16) -> bool {
        if !self.enabled {
            return false;
        }
        if self.exclude.iter().any(|p| pattern_matches(p, host, port)) {
            return false;
        }
        self.include.iter().any(|p| pattern_matches(p, host, port))
    }
}

/// Матч одного паттерна Charles против host:port (регистронезависимо).
pub fn pattern_matches(pattern: &str, host: &str, port: u16) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let (hp, pp) = match pattern.rsplit_once(':') {
        Some((h, p)) => (h.trim(), Some(p.trim())),
        None => (pattern, None),
    };
    let host_ok = if hp == "*" || hp.is_empty() {
        true
    } else if let Some(suf) = hp.strip_prefix("*.") {
        let h = host.to_ascii_lowercase();
        let s = suf.to_ascii_lowercase();
        h == s || h.ends_with(&format!(".{s}"))
    } else {
        hp.eq_ignore_ascii_case(host)
    };
    if !host_ok {
        return false;
    }
    match pp {
        None => true,
        Some(p) if p == "*" || p.is_empty() => true,
        Some(p) => p.parse::<u16>().is_ok_and(|pn| pn == port),
    }
}
