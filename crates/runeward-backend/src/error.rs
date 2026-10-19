//! The error type shared by every backend.

use std::io;

/// Errors returned by [`crate::Backend`] implementations and helpers.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// A failure described by a message (CLI stderr, validation, state).
    #[error("{0}")]
    Message(String),
    /// An I/O failure with context.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A Kubernetes API failure with context.
    #[error("{context}: {source}")]
    Kube {
        /// What was being attempted.
        context: String,
        /// The underlying error.
        #[source]
        source: Box<kube::Error>,
    },
    /// The sandbox (or another named object) does not exist.
    #[error("{0}")]
    NotFound(String),
    /// An operation ran past its deadline.
    #[error("{0}")]
    Timeout(String),
    /// The backend does not support the requested operation or setting.
    #[error("{0}")]
    Unsupported(String),
}

impl BackendError {
    /// Builds a [`BackendError::Message`].
    pub fn msg(m: impl Into<String>) -> Self {
        Self::Message(m.into())
    }

    /// Wraps an I/O error with context.
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Wraps a Kubernetes client error with context.
    pub fn kube(context: impl Into<String>, source: kube::Error) -> Self {
        Self::Kube {
            context: context.into(),
            source: Box::new(source),
        }
    }

    /// Reports whether the error is a Kubernetes 404.
    pub fn is_kube_not_found(&self) -> bool {
        matches!(self, Self::Kube { source, .. } if is_status(source, 404))
    }
}

/// Reports whether a kube error is an API response with `code`.
pub(crate) fn is_status(err: &kube::Error, code: u16) -> bool {
    matches!(err, kube::Error::Api(resp) if resp.code == code)
}

/// Result alias for backend operations.
pub type Result<T, E = BackendError> = std::result::Result<T, E>;
