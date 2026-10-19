//! The per-sandbox certificate authority used to terminate TLS for
//! inspected endpoints. The sandbox trusts it (its PEM is mounted into the
//! trust store); nothing else does, and its key never leaves the broker.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// CA lifetime.
pub const CA_VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Leaf lifetime; leaves are re-minted well before they expire.
pub const LEAF_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const LEAF_REFRESH: Duration = Duration::from_secs(6 * 24 * 60 * 60);

/// Errors minting certificates.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// Certificate generation failed.
    #[error("certificate generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// The minted certificate was rejected by rustls.
    #[error("tls config: {0}")]
    Tls(#[from] rustls::Error),
}

/// A per-sandbox CA that mints and caches leaf certificates per host.
pub struct SandboxCa {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, (Instant, Arc<rustls::ServerConfig>)>>,
}

impl std::fmt::Debug for SandboxCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxCa").finish_non_exhaustive()
    }
}

fn common_name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn random_serial() -> SerialNumber {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] &= 0x7f;
    b[0] |= 0x01;
    SerialNumber::from_slice(&b)
}

impl SandboxCa {
    /// Generates a fresh ECDSA P-256 CA for `sandbox_id`.
    pub fn generate(sandbox_id: &str) -> Result<Self, CaError> {
        let not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let label = if sandbox_id.trim().is_empty() {
            "runeward-egress broker CA".to_string()
        } else {
            format!("runeward-egress broker CA {}", sandbox_id.trim())
        };
        params.distinguished_name = common_name(&label);
        params.serial_number = Some(random_serial());
        params.not_before = not_before;
        params.not_after = not_before + CA_VALIDITY;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key)?;
        Ok(Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: Issuer::new(params, key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate (PEM) to mount into the sandbox trust store.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate (DER).
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// A TLS server config presenting a leaf for `host` (DNS name or IP),
    /// minted on first use and cached.
    pub fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, CaError> {
        let host = host.trim().to_ascii_lowercase();
        {
            let leaves = self.leaves.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, cfg)) = leaves.get(&host)
                && at.elapsed() < LEAF_REFRESH
            {
                return Ok(Arc::clone(cfg));
            }
        }
        let cfg = Arc::new(self.mint(&host)?);
        self.leaves
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(host, (Instant::now(), Arc::clone(&cfg)));
        Ok(cfg)
    }

    fn mint(&self, host: &str) -> Result<rustls::ServerConfig, CaError> {
        let not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        // rcgen turns IP literals into IP SANs and everything else into DNS
        // SANs.
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name = common_name(host);
        params.serial_number = Some(random_serial());
        params.not_before = not_before;
        params.not_after = not_before + LEAF_VALIDITY;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.issuer)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone(), self.cert_der.clone()], key_der)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints_and_caches_leaves() {
        let ca = SandboxCa::generate("sb-ca").expect("ca");
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        let a = ca.server_config("API.example.test").expect("leaf");
        let b = ca.server_config("api.example.test").expect("leaf");
        assert!(Arc::ptr_eq(&a, &b), "cached per host");
        let ip = ca.server_config("127.0.0.1").expect("ip leaf");
        assert!(!Arc::ptr_eq(&a, &ip));
    }
}
