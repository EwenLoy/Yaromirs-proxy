//! Тесты rproxy-cert: генерация CA и leaf-сертификатов.

use rproxy_cert::CertAuthority;

#[test]
fn ca_generation_and_leaf_certs() {
    let ca = CertAuthority::generate().expect("CA generation");
    let pem = ca.ca_cert_pem();
    assert!(pem.contains("BEGIN CERTIFICATE"));

    // leaf для DNS-хоста
    let (chain, key) = ca.leaf_for("example.com").expect("leaf");
    assert_eq!(chain.len(), 2, "leaf + CA");
    assert!(!key.is_empty());

    // leaf для IP-хоста
    let (chain, _) = ca.leaf_for("127.0.0.1").expect("leaf ip");
    assert_eq!(chain.len(), 2);

    // детерминированность: один и тот же CA подписывает разные хосты
    let (_, key2) = ca.leaf_for("other.example.org").expect("leaf 2");
    assert!(!key2.is_empty());
}
