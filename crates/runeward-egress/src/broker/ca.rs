//! The per-sandbox certificate authority used to terminate TLS for
//! inspected endpoints. The sandbox trusts it (its PEM is mounted into the
//! trust store); nothing else does, and its key never leaves the broker.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::TryRng;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls::pki_types::pem::PemObject as _;
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
    /// An imported CA certificate and key do not belong together.
    #[error("broker CA: {0}")]
    Mismatch(String),
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
    rand::rngs::SysRng
        .try_fill_bytes(&mut b)
        .expect("system random source");
    b[0] &= 0x7f;
    b[0] |= 0x01;
    SerialNumber::from_slice(&b)
}

impl SandboxCa {
    /// Generates a fresh ECDSA P-256 CA for `sandbox_id`.
    pub fn generate(sandbox_id: &str) -> Result<Self, CaError> {
        let not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = ca_params(sandbox_id)?;
        params.serial_number = Some(random_serial());
        params.not_before = not_before;
        params.not_after = not_before + CA_VALIDITY;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let cert = params.self_signed(&key)?;
        Ok(Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: Issuer::new(params, key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// Rebuilds the CA a control plane generated with [`SandboxCa::generate`]
    /// for the same `sandbox_id`, from its certificate and private key (as
    /// exported by [`SandboxCa::key_pem`]). This is how an out-of-process
    /// sidecar serves the CA the sandbox already trusts.
    ///
    /// The pair is checked before it is accepted: a leaf minted with the key
    /// must validate against the certificate, so a mismatched or foreign
    /// pair fails closed.
    pub fn from_pem(sandbox_id: &str, cert_pem: &str, key_pem: &str) -> Result<Self, CaError> {
        let key = KeyPair::from_pem(key_pem)?;
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| CaError::Mismatch(format!("parse CA certificate: {e}")))?;
        let ca = Self {
            cert_pem: cert_pem.to_string(),
            cert_der,
            issuer: Issuer::new(ca_params(sandbox_id)?, key),
            leaves: Mutex::new(HashMap::new()),
        };
        ca.check_pair()?;
        Ok(ca)
    }

    /// PEM of the CA private key. Only the control plane uses this, to hand
    /// the CA to an egress sidecar; it must never reach the sandbox.
    pub fn key_pem(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.issuer.key().serialize_pem())
    }

    /// Mints a throwaway leaf and validates it against the CA certificate.
    fn check_pair(&self) -> Result<(), CaError> {
        use rustls::client::danger::ServerCertVerifier as _;
        const PROBE: &str = "ca-check.runeward.invalid";
        let leaf = self.mint_leaf(PROBE)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.cert_der.clone())
            .map_err(|e| CaError::Mismatch(format!("CA certificate: {e}")))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| CaError::Mismatch(e.to_string()))?;
        let name = rustls::pki_types::ServerName::try_from(PROBE)
            .map_err(|e| CaError::Mismatch(e.to_string()))?;
        verifier
            .verify_server_cert(&leaf.0, &[], &name, &[], rustls::pki_types::UnixTime::now())
            .map_err(|e| {
                CaError::Mismatch(format!(
                    "the CA key does not match the CA certificate (or the sandbox id differs): {e}"
                ))
            })?;
        Ok(())
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
        let (leaf, key_der) = self.mint_leaf(host)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf, self.cert_der.clone()], key_der)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(cfg)
    }

    fn mint_leaf(
        &self,
        host: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CaError> {
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
        Ok((cert.der().clone(), key_der))
    }
}

/// The CA subject and key usages for `sandbox_id`. The subject must be the
/// same on generate and import, since minted leaves name it as issuer.
fn ca_params(sandbox_id: &str) -> Result<CertificateParams, CaError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let label = if sandbox_id.trim().is_empty() {
        "runeward-egress broker CA".to_string()
    } else {
        format!("runeward-egress broker CA {}", sandbox_id.trim())
    };
    params.distinguished_name = common_name(&label);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
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

    #[test]
    fn exports_and_reimports_the_pair() {
        let ca = SandboxCa::generate("sb-export").expect("ca");
        let key = ca.key_pem();
        assert!(key.contains("PRIVATE KEY"));
        let back = SandboxCa::from_pem("sb-export", ca.cert_pem(), &key).expect("import");
        assert_eq!(back.cert_pem(), ca.cert_pem());
        back.server_config("api.example.test").expect("leaf");

        // A foreign key, or a different sandbox id (subject), is refused.
        let other = SandboxCa::generate("sb-export").expect("other");
        let err = SandboxCa::from_pem("sb-export", ca.cert_pem(), &other.key_pem())
            .expect_err("foreign key");
        assert!(matches!(err, CaError::Mismatch(_)), "{err}");
        assert!(SandboxCa::from_pem("sb-other", ca.cert_pem(), &key).is_err());
        assert!(SandboxCa::from_pem("sb-export", "not pem", &key).is_err());
    }
}
