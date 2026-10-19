//! The control plane's error type.

use runeward_fleet::FleetError;

/// Errors returned by [`crate::Manager`].
///
/// [`Error::NotFound`] and [`Error::BadInput`] carry messages that are safe
/// to show an API caller (Go's `ClientError`); [`Error::Other`] may embed
/// host paths or backend detail and must stay opaque at the transport
/// boundary. [`Error::client_status`] maps each variant to the HTTP status
/// the Go server used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A missing resource (sandbox, run, snapshot, browser session).
    #[error("{0}")]
    NotFound(String),
    /// Caller-supplied input the control plane rejected.
    #[error("{0}")]
    BadInput(String),
    /// A Cohort board operation failed (unknown task, illegal transition).
    #[error(transparent)]
    Task(#[from] FleetError),
    /// A task lease token was invalid, expired, or bound to something else.
    #[error("cohort: invalid or expired task lease")]
    InvalidLease,
    /// The backend could not provide the Charter's `[isolation] minimum`.
    /// The sandbox was torn down before anything ran in it.
    #[error(
        "charter {charter:?} requires isolation {required:?} but the {backend} backend provided {actual:?}; configure a stronger runtime (for example host.runtime_class) or lower [isolation] minimum"
    )]
    IsolationFloor {
        /// Charter name.
        charter: String,
        /// The configured floor.
        required: String,
        /// The tier the backend reported for the new sandbox.
        actual: String,
        /// Backend name.
        backend: String,
    },
    /// Any other failure: backend, filesystem, ledger or configuration.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// An opaque failure described by `msg`.
    pub fn other(msg: impl std::fmt::Display) -> Self {
        Self::Other(msg.to_string())
    }

    pub(crate) fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub(crate) fn bad_input(msg: impl Into<String>) -> Self {
        Self::BadInput(msg.into())
    }

    /// Reports whether the message is safe to return to an API caller.
    pub fn is_client_error(&self) -> bool {
        self.client_status().is_some()
    }

    /// The HTTP status a transport should use for this error, or `None` for
    /// an internal failure (500 with an opaque body).
    pub fn client_status(&self) -> Option<u16> {
        match self {
            Self::NotFound(_) | Self::Task(FleetError::NotFound(_)) => Some(404),
            Self::BadInput(_) => Some(400),
            Self::Task(FleetError::IllegalTransition(_)) => Some(409),
            Self::InvalidLease => Some(401),
            Self::IsolationFloor { .. } | Self::Other(_) => None,
        }
    }
}

impl From<runeward_backend::BackendError> for Error {
    fn from(e: runeward_backend::BackendError) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<runeward_ledger::LedgerError> for Error {
    fn from(e: runeward_ledger::LedgerError) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.to_string())
    }
}

/// Result alias for control-plane operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_go_server() {
        assert_eq!(Error::not_found("x").client_status(), Some(404));
        assert_eq!(Error::bad_input("x").client_status(), Some(400));
        assert_eq!(Error::InvalidLease.client_status(), Some(401));
        assert_eq!(
            Error::Task(FleetError::IllegalTransition("x".into())).client_status(),
            Some(409)
        );
        assert_eq!(Error::other("boom").client_status(), None);
        assert_eq!(
            Error::InvalidLease.to_string(),
            "cohort: invalid or expired task lease"
        );
    }
}
