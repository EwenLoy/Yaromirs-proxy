//! rproxy-cert — генерация root CA и динамических leaf-сертификатов (tech-plan.md §4).
//! CA сохраняется на диск (%USERPROFILE%\.rproxy или RPROXY_CA_DIR), чтобы сертификат
//! не менялся между запусками и его можно было один раз доверить в системе.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;

/// Root CA прокси: PEM-сертификат + PEM-ключ (PKCS#8).
#[derive(Clone)]
pub struct CertAuthority {
    ca_cert_pem: String,
    ca_key_pem: String,
}

impl CertAuthority {
    /// Загрузить CA с диска или сгенерировать и сохранить.
    pub fn load_or_create(dir: &Path) -> io::Result<Self> {
        let cert_path = dir.join("ca.cert.pem");
        let key_path = dir.join("ca.key.pem");
        if let (Ok(cert), Ok(key)) = (fs::read_to_string(&cert_path), fs::read_to_string(&key_path)) {
            return Ok(Self {
                ca_cert_pem: cert,
                ca_key_pem: key,
            });
        }
        let ca = Self::generate()
            .map_err(|e| io::Error::other(format!("CA generation failed: {e}")))?;
        fs::create_dir_all(dir)?;
        fs::write(&cert_path, &ca.ca_cert_pem)?;
        fs::write(&key_path, &ca.ca_key_pem)?;
        Ok(ca)
    }

    /// Сгенерировать новый self-signed CA.
    pub fn generate() -> Result<Self, rcgen::Error> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "rproxy Root CA");
        params.distinguished_name.push(DnType::OrganizationName, "rproxy");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(Self {
            ca_cert_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        })
    }

    /// PEM корневого сертификата (для экспорта/доверия в системе).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, rcgen::Error> {
        let key = KeyPair::from_pem(&self.ca_key_pem)?;
        Issuer::from_ca_cert_pem(&self.ca_cert_pem, key)
    }

    /// Сгенерировать leaf-сертификат для хоста: цепочка (leaf + CA) в DER и ключ (PKCS#8 DER).
    pub fn leaf_for(
        &self,
        host: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, Vec<u8>), rcgen::Error> {
        let issuer = self.issuer()?;

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        match host.parse::<std::net::IpAddr>() {
            Ok(ip) => params.subject_alt_names = vec![SanType::IpAddress(ip)],
            Err(_) => {
                params.subject_alt_names =
                    vec![SanType::DnsName(host.try_into()?)];
            }
        }
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(825);
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_key = KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &issuer)?;

        let ca_der = pem_to_der(&self.ca_cert_pem);
        Ok((
            vec![leaf.der().clone(), ca_der],
            leaf_key.serialize_der(),
        ))
    }
}

/// Первый PEM-блок CERTIFICATE -> DER.
fn pem_to_der(pem: &str) -> CertificateDer<'static> {
    let mut cursor = io::Cursor::new(pem.as_bytes());
    let der = rustls_pemfile::certs(&mut cursor)
        .next()
        .expect("no CERTIFICATE block in PEM")
        .expect("invalid PEM");
    der
}

/// Директория хранения CA: RPROXY_CA_DIR или ~/.rproxy.
pub fn default_ca_dir() -> Option<std::path::PathBuf> {
    if let Ok(d) = std::env::var("RPROXY_CA_DIR") {
        return Some(std::path::PathBuf::from(d));
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()?;
    Some(PathBuf::from(home).join(".rproxy"))
}
