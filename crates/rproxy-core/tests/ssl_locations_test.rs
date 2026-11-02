//! Тесты SSL-локаций в стиле Charles (tech-plan.md §12.2).

use rproxy_core::ssl_proxy::pattern_matches;
use rproxy_core::SslProxyConfig;

#[test]
fn wildcard_matches_everything() {
    assert!(pattern_matches("*:*", "example.com", 443));
    assert!(pattern_matches("*", "anything.io", 80));
    assert!(pattern_matches("", "example.com", 443) == false);
}

#[test]
fn host_and_port_patterns() {
    assert!(pattern_matches("example.com", "example.com", 443));
    assert!(pattern_matches("example.com", "EXAMPLE.com", 443));
    assert!(pattern_matches("example.com:443", "example.com", 443));
    assert!(!pattern_matches("example.com:443", "example.com", 80));
    assert!(pattern_matches("*.example.com:*", "api.example.com", 8443));
    assert!(pattern_matches("*.example.com:*", "example.com", 443));
    assert!(!pattern_matches("*.example.com:*", "example.org", 443));
}

#[test]
fn include_exclude_config() {
    let mut cfg = SslProxyConfig::default();
    assert!(cfg.should_mitm("a.test", 443));
    cfg.enabled = false;
    assert!(!cfg.should_mitm("a.test", 443));
    cfg.enabled = true;
    cfg.exclude.push("blocked.test:*".to_string());
    assert!(!cfg.should_mitm("blocked.test", 443));
    assert!(cfg.should_mitm("other.test", 443));
    cfg.include = vec!["only.test:*".to_string()];
    assert!(cfg.should_mitm("only.test", 443));
    assert!(!cfg.should_mitm("other.test", 443));
}
