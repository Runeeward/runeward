//! Self-signed CA and serving certificate for the webhook.

use rand::Rng;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use std::time::Duration;

/// How long the generated CA and leaf certificate stay valid.
pub const CERT_VALIDITY: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// A PEM-encoded serving certificate, its private key, and the CA that signed
/// it (published as the webhook `caBundle`).
#[derive(Clone, PartialEq, Eq)]
pub struct CertBundle {
    /// Leaf certificate (`CERTIFICATE` PEM block).
    pub cert_pem: Vec<u8>,
    /// Leaf private key (`EC PRIVATE KEY` PEM block for keys this crate
    /// mints; any key format rustls understands is accepted on load).
    pub key_pem: Vec<u8>,
    /// CA certificate (`CERTIFICATE` PEM block).
    pub ca_pem: Vec<u8>,
}

impl std::fmt::Debug for CertBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertBundle")
            .field("cert_pem", &String::from_utf8_lossy(&self.cert_pem))
            .field("key_pem", &"<redacted>")
            .field("ca_pem", &String::from_utf8_lossy(&self.ca_pem))
            .finish()
    }
}

/// Mints an ECDSA P-256 CA plus a leaf serving certificate for `dns_names`
/// (typically `<svc>.<ns>.svc` and `<svc>.<ns>.svc.cluster.local`).
///
/// Mirrors the Go webhook: CA CN `runeward-webhook-ca`; leaf CN is the first
/// DNS name (or `runeward-webhook`), key usage digitalSignature +
/// keyEncipherment, EKU serverAuth; validity starts one minute in the past and
/// lasts [`CERT_VALIDITY`]; serials are random positive 128-bit integers.
pub fn generate_cert(dns_names: &[String]) -> Result<CertBundle, rcgen::Error> {
    let not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let not_after = not_before + CERT_VALIDITY;

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.distinguished_name = common_name("runeward-webhook-ca");
    ca.serial_number = Some(random_serial());
    ca.not_before = not_before;
    ca.not_after = not_after;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca.self_signed(&ca_key)?;

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut leaf = CertificateParams::new(dns_names.to_vec())?;
    let cn = dns_names.first().map_or("runeward-webhook", String::as_str);
    leaf.distinguished_name = common_name(cn);
    leaf.serial_number = Some(random_serial());
    leaf.not_before = not_before;
    leaf.not_after = not_after;
    leaf.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    let issuer = Issuer::new(ca, ca_key);
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer)?;

    let key_pem = match pkcs8_p256_to_sec1(leaf_key.serialized_der()) {
        Some(sec1) => pem_block("EC PRIVATE KEY", &sec1),
        None => leaf_key.serialize_pem(),
    };
    Ok(CertBundle {
        cert_pem: leaf_cert.pem().into_bytes(),
        key_pem: key_pem.into_bytes(),
        ca_pem: ca_cert.pem().into_bytes(),
    })
}

fn common_name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn random_serial() -> SerialNumber {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    // Keep it positive; strip leading zero bytes for a minimal encoding.
    b[0] &= 0x7f;
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
    SerialNumber::from_slice(&b[start..])
}

/// The fixed prefix of ring's PKCS#8 v1 encoding of a P-256 key, up to the
/// inner ECPrivateKey's private scalar.
const PKCS8_P256_PREFIX: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20,
];
/// Between the scalar and the public key: `[1] { BIT STRING (0 unused bits) 04 ... }`.
const PKCS8_P256_PUB_PREFIX: &[u8] = &[0xa1, 0x44, 0x03, 0x42, 0x00];
/// `id-ecPublicKey` parameters: OID prime256v1.
const P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Re-encodes a P-256 PKCS#8 key as the SEC1 `ECPrivateKey` (with curve
/// parameters and public key) that Go's `x509.MarshalECPrivateKey` writes,
/// so Secrets minted here are byte-compatible with the Go webhook's.
fn pkcs8_p256_to_sec1(pkcs8: &[u8]) -> Option<Vec<u8>> {
    let rest = pkcs8.strip_prefix(PKCS8_P256_PREFIX)?;
    let (scalar, rest) = rest.split_at_checked(32)?;
    let point = rest.strip_prefix(PKCS8_P256_PUB_PREFIX)?;
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    let mut out = Vec::with_capacity(121);
    out.extend_from_slice(&[0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]);
    out.extend_from_slice(scalar);
    out.extend_from_slice(&[0xa0, 0x0a]);
    out.extend_from_slice(P256_OID);
    out.extend_from_slice(PKCS8_P256_PUB_PREFIX);
    out.extend_from_slice(point);
    Some(out)
}

fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    #[test]
    fn generate_cert_without_names() {
        let b = generate_cert(&[]).expect("generate_cert(nil)");
        assert!(!b.cert_pem.is_empty() && !b.key_pem.is_empty() && !b.ca_pem.is_empty());
    }

    #[test]
    fn generate_cert_blocks_and_key_format() {
        let names = vec![
            "svc.ns.svc".to_owned(),
            "svc.ns.svc.cluster.local".to_owned(),
        ];
        let b = generate_cert(&names).expect("generate_cert");
        for (name, pem) in [
            ("cert", &b.cert_pem),
            ("key", &b.key_pem),
            ("ca", &b.ca_pem),
        ] {
            assert!(!pem.is_empty(), "{name} PEM is empty");
        }
        let key = String::from_utf8(b.key_pem.clone()).expect("utf8");
        assert!(key.starts_with("-----BEGIN EC PRIVATE KEY-----\n"), "{key}");
        assert!(matches!(
            PrivateKeyDer::from_pem_slice(&b.key_pem).expect("parse key"),
            PrivateKeyDer::Sec1(_)
        ));
        assert_eq!(
            CertificateDer::pem_slice_iter(&b.cert_pem).count(),
            1,
            "one leaf cert"
        );
    }

    #[test]
    fn leaf_chains_to_ca_and_serves_tls() {
        let names = vec!["svc.ns.svc".to_owned()];
        let b = generate_cert(&names).expect("generate_cert");
        // The leaf + key must load into a ring-backed rustls server config.
        super::super::server::tls_config(&b).expect("tls config");

        // And verify against the CA as a client would.
        let mut roots = rustls::RootCertStore::empty();
        for ca in CertificateDer::pem_slice_iter(&b.ca_pem) {
            roots.add(ca.expect("ca")).expect("add root");
        }
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            std::sync::Arc::new(roots),
            provider,
        )
        .build()
        .expect("verifier");
        let leaf = CertificateDer::from_pem_slice(&b.cert_pem).expect("leaf");
        use rustls::client::danger::ServerCertVerifier as _;
        verifier
            .verify_server_cert(
                &leaf,
                &[],
                &rustls::pki_types::ServerName::try_from("svc.ns.svc").expect("name"),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .expect("leaf verifies against CA");
    }
}
