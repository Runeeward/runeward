//! The minimal content-store abstraction bundles are pushed to and pulled
//! from (a subset of oras-go's `Target`), plus a test-only in-memory store.

use std::future::Future;

use crate::digest;
use crate::manifest::Descriptor;

/// Largest manifest accepted on pull (oras-go's `FetchBytes` default).
pub(crate) const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// A content store failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The requested tag, digest or blob does not exist.
    #[error("{0}: not found")]
    NotFound(String),
    /// Content length differs from the descriptor size.
    #[error("content size {actual} does not match descriptor size {expected}")]
    SizeMismatch {
        /// Size recorded in the descriptor.
        expected: i64,
        /// Size of the fetched bytes.
        actual: usize,
    },
    /// Content hashes to a different digest than the descriptor records.
    #[error("content digest {actual} does not match descriptor digest {expected}")]
    DigestMismatch {
        /// Digest recorded in the descriptor.
        expected: String,
        /// Digest of the fetched bytes.
        actual: String,
    },
    /// A digest is malformed or uses an unsupported algorithm.
    #[error("invalid digest {digest:?}: {reason}")]
    InvalidDigest {
        /// The offending digest.
        digest: String,
        /// Why it was rejected.
        reason: String,
    },
    /// Content exceeds the size limit.
    #[error("content size exceeds limit {limit} bytes")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The registry request failed.
    #[error(transparent)]
    Registry(#[from] oci_client::errors::OciDistributionError),
    /// A local I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Checks `data` against the size and digest recorded in `desc`.
pub(crate) fn verify_content(desc: &Descriptor, data: &[u8]) -> Result<(), StoreError> {
    if usize::try_from(desc.size).ok() != Some(data.len()) {
        return Err(StoreError::SizeMismatch {
            expected: desc.size,
            actual: data.len(),
        });
    }
    verify_digest(&desc.digest, data)
}

/// Checks that `data` hashes to `expected`.
pub(crate) fn verify_digest(expected: &str, data: &[u8]) -> Result<(), StoreError> {
    let actual =
        digest::compute_like(expected, data).map_err(|reason| StoreError::InvalidDigest {
            digest: expected.to_owned(),
            reason,
        })?;
    if actual != expected {
        return Err(StoreError::DigestMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

/// A content-addressed store holding blobs, manifests and tags.
pub(crate) trait Target: Sync {
    /// Stores a blob under its descriptor.
    fn push_blob(
        &self,
        desc: &Descriptor,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stores a manifest under its digest and, when `tag` is set, tags it.
    fn push_manifest(
        &self,
        desc: &Descriptor,
        data: Vec<u8>,
        tag: Option<&str>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Resolves a tag or digest and returns the manifest's digest and bytes.
    fn fetch_manifest(
        &self,
        reference: &str,
    ) -> impl Future<Output = Result<(String, Vec<u8>), StoreError>> + Send;

    /// Returns the bytes of the blob `desc` names.
    fn fetch_blob(
        &self,
        desc: &Descriptor,
    ) -> impl Future<Output = Result<Vec<u8>, StoreError>> + Send;
}

#[cfg(test)]
pub(crate) use memory::MemoryStore;

#[cfg(test)]
mod memory {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{Descriptor, StoreError, Target, verify_content};

    /// An in-memory [`Target`] for tests, the equivalent of oras-go's `memory.Store`.
    #[derive(Debug, Default)]
    pub(crate) struct MemoryStore {
        inner: Mutex<MemoryInner>,
    }

    #[derive(Debug, Default)]
    struct MemoryInner {
        content: HashMap<String, Vec<u8>>,
        tags: HashMap<String, String>,
    }

    impl MemoryStore {
        fn lock(&self) -> std::sync::MutexGuard<'_, MemoryInner> {
            self.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        /// Points `tag` at an already-stored manifest.
        pub(crate) fn tag(&self, digest: &str, tag: &str) {
            self.lock().tags.insert(tag.to_owned(), digest.to_owned());
        }
    }

    impl Target for MemoryStore {
        async fn push_blob(&self, desc: &Descriptor, data: Vec<u8>) -> Result<(), StoreError> {
            verify_content(desc, &data)?;
            self.lock().content.insert(desc.digest.clone(), data);
            Ok(())
        }

        async fn push_manifest(
            &self,
            desc: &Descriptor,
            data: Vec<u8>,
            tag: Option<&str>,
        ) -> Result<(), StoreError> {
            verify_content(desc, &data)?;
            let mut inner = self.lock();
            inner.content.insert(desc.digest.clone(), data);
            if let Some(tag) = tag {
                inner.tags.insert(tag.to_owned(), desc.digest.clone());
            }
            Ok(())
        }

        async fn fetch_manifest(&self, reference: &str) -> Result<(String, Vec<u8>), StoreError> {
            let inner = self.lock();
            let digest = inner
                .tags
                .get(reference)
                .cloned()
                .unwrap_or_else(|| reference.to_owned());
            let data = inner
                .content
                .get(&digest)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(reference.to_owned()))?;
            Ok((digest, data))
        }

        async fn fetch_blob(&self, desc: &Descriptor) -> Result<Vec<u8>, StoreError> {
            self.lock()
                .content
                .get(&desc.digest)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(desc.digest.clone()))
        }
    }
}
