//! Persisting the serving certificate in a Secret so it survives restarts and
//! is shared by every replica.

use super::Error;
use super::cert::{CertBundle, generate_cert};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ObjectMeta, PostParams};
use std::collections::BTreeMap;

/// Secret data key of the leaf certificate.
pub const CERT_SECRET_CERT_KEY: &str = "tls.crt";
/// Secret data key of the leaf private key.
pub const CERT_SECRET_KEY_KEY: &str = "tls.key";
/// Secret data key of the CA certificate.
pub const CERT_SECRET_CA_KEY: &str = "ca.crt";

/// Returns a serving certificate that is stable across restarts and shared by
/// every webhook replica. It reads the named Secret; if the Secret already
/// holds a complete cert it is reused, otherwise a fresh cert is generated and
/// stored. On a create race (another replica won), the winner's Secret is read
/// back, so all replicas converge on one CA, which is what makes running more
/// than one replica behind the Service safe.
///
/// When `client` is `None` (no cluster access) or `secret_name` is empty it
/// falls back to an ephemeral, in-memory cert.
pub async fn load_or_create_cert(
    client: Option<kube::Client>,
    namespace: &str,
    secret_name: &str,
    dns_names: &[String],
) -> Result<CertBundle, Error> {
    let Some(client) = client.filter(|_| !secret_name.is_empty()) else {
        return generate_cert(dns_names).map_err(Error::Cert);
    };
    let secrets: Api<Secret> = Api::namespaced(client, namespace);

    match secrets.get(secret_name).await {
        Ok(existing) => {
            if let Some(b) = cert_from_secret(&existing) {
                return Ok(b);
            }
        }
        Err(e) if is_status(&e, 404) => {}
        Err(e) => {
            return Err(Error::Kube {
                context: format!("read cert secret {secret_name:?}"),
                error: Box::new(e),
            });
        }
    }

    let bundle = generate_cert(dns_names).map_err(Error::Cert)?;
    let sec = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_owned(),
                "runeward".to_owned(),
            )])),
            ..ObjectMeta::default()
        },
        type_: Some("kubernetes.io/tls".to_owned()),
        data: Some(BTreeMap::from([
            (
                CERT_SECRET_CERT_KEY.to_owned(),
                ByteString(bundle.cert_pem.clone()),
            ),
            (
                CERT_SECRET_KEY_KEY.to_owned(),
                ByteString(bundle.key_pem.clone()),
            ),
            (
                CERT_SECRET_CA_KEY.to_owned(),
                ByteString(bundle.ca_pem.clone()),
            ),
        ])),
        ..Secret::default()
    };
    match secrets.create(&PostParams::default(), &sec).await {
        Ok(_) => Ok(bundle),
        Err(e) if is_status(&e, 409) => {
            // Lost the race: adopt the cert another replica just stored.
            let existing = secrets.get(secret_name).await.map_err(|e| Error::Kube {
                context: format!("read cert secret {secret_name:?} after race"),
                error: Box::new(e),
            })?;
            cert_from_secret(&existing).ok_or_else(|| {
                Error::Other(format!(
                    "cert secret {secret_name:?} exists but is incomplete"
                ))
            })
        }
        Err(e) => Err(Error::Kube {
            context: format!("persist cert secret {secret_name:?}"),
            error: Box::new(e),
        }),
    }
}

/// Extracts the cert triple from a Secret, or `None` if any part is missing
/// or empty.
pub fn cert_from_secret(s: &Secret) -> Option<CertBundle> {
    let data = s.data.as_ref()?;
    let get = |k: &str| data.get(k).map(|b| b.0.clone()).filter(|b| !b.is_empty());
    Some(CertBundle {
        cert_pem: get(CERT_SECRET_CERT_KEY)?,
        key_pem: get(CERT_SECRET_KEY_KEY)?,
        ca_pem: get(CERT_SECRET_CA_KEY)?,
    })
}

pub(crate) fn is_status(e: &kube::Error, code: u16) -> bool {
    matches!(e, kube::Error::Api(ae) if ae.code == code)
}
