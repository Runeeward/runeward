//! A [`Target`] backed by an OCI distribution registry via `oci-client`.
//!
//! Like oras-go's `remote.NewRepository` with its default client, access is
//! anonymous: bearer-token challenges are answered without credentials and no
//! Docker config file is read.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::HeaderValue;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference as OciReference};
use tokio::io::AsyncWrite;

use crate::manifest::{Descriptor, MANIFEST_ACCEPT};
use crate::reference::Reference;
use crate::store::{MAX_MANIFEST_BYTES, StoreError, Target};

/// One repository on a remote registry.
pub(crate) struct Repository {
    client: Client,
    registry: String,
    repository: String,
}

impl std::fmt::Debug for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repository")
            .field("registry", &self.registry)
            .field("repository", &self.repository)
            .finish_non_exhaustive()
    }
}

impl Repository {
    /// Connects anonymously to `reference`'s repository, over plain HTTP when
    /// `plain_http` is set.
    pub async fn new(reference: &Reference, plain_http: bool) -> Self {
        // reqwest is built without a bundled crypto provider; use ring like
        // the rest of the workspace. Failure means one is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::new(ClientConfig {
            protocol: if plain_http {
                ClientProtocol::Http
            } else {
                ClientProtocol::Https
            },
            // oras-go uploads each blob with a single PUT.
            use_monolithic_push: true,
            ..ClientConfig::default()
        });
        let repo = Self {
            client,
            registry: reference.registry.clone(),
            repository: reference.repository.clone(),
        };
        let probe = repo.by_tag("latest");
        repo.client
            .store_auth_if_needed(probe.resolve_registry(), &RegistryAuth::Anonymous)
            .await;
        repo
    }

    fn by_digest(&self, digest: &str) -> OciReference {
        OciReference::with_digest(
            self.registry.clone(),
            self.repository.clone(),
            digest.to_owned(),
        )
    }

    fn by_tag(&self, tag: &str) -> OciReference {
        OciReference::with_tag(
            self.registry.clone(),
            self.repository.clone(),
            tag.to_owned(),
        )
    }

    fn resolve(&self, reference: &str) -> OciReference {
        if reference.contains(':') {
            self.by_digest(reference)
        } else {
            self.by_tag(reference)
        }
    }
}

fn content_type(media_type: &str) -> Result<HeaderValue, StoreError> {
    HeaderValue::from_str(media_type).map_err(|e| {
        StoreError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("media type {media_type:?}: {e}"),
        ))
    })
}

impl Target for Repository {
    async fn push_blob(&self, desc: &Descriptor, data: Vec<u8>) -> Result<(), StoreError> {
        self.client
            .push_blob(&self.by_digest(&desc.digest), data, &desc.digest)
            .await?;
        Ok(())
    }

    async fn push_manifest(
        &self,
        desc: &Descriptor,
        data: Vec<u8>,
        tag: Option<&str>,
    ) -> Result<(), StoreError> {
        let ct = content_type(&desc.media_type)?;
        self.client
            .push_manifest_raw(&self.by_digest(&desc.digest), data.clone(), ct.clone())
            .await?;
        if let Some(tag) = tag {
            self.client
                .push_manifest_raw(&self.by_tag(tag), data, ct)
                .await?;
        }
        Ok(())
    }

    async fn fetch_manifest(&self, reference: &str) -> Result<(String, Vec<u8>), StoreError> {
        let (body, digest) = self
            .client
            .pull_manifest_raw(
                &self.resolve(reference),
                &RegistryAuth::Anonymous,
                MANIFEST_ACCEPT,
            )
            .await?;
        if body.len() > MAX_MANIFEST_BYTES {
            return Err(StoreError::TooLarge {
                limit: MAX_MANIFEST_BYTES,
            });
        }
        Ok((digest, body.to_vec()))
    }

    async fn fetch_blob(&self, desc: &Descriptor) -> Result<Vec<u8>, StoreError> {
        let limit = usize::try_from(desc.size).unwrap_or(0);
        let mut out = LimitedBuf {
            buf: Vec::new(),
            limit,
        };
        self.client
            .pull_blob(
                &self.by_digest(&desc.digest),
                desc.digest.as_str(),
                &mut out,
            )
            .await?;
        Ok(out.buf)
    }
}

/// An in-memory sink that refuses to grow past the descriptor size, so a
/// hostile registry cannot stream an unbounded blob.
struct LimitedBuf {
    buf: Vec<u8>,
    limit: usize,
}

impl AsyncWrite for LimitedBuf {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.buf.len() + data.len() > this.limit {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("blob exceeds descriptor size {}", this.limit),
            )));
        }
        this.buf.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
