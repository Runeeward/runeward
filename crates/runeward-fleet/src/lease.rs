//! Signed Cohort task leases.
//!
//! A lease token is `b64url(JSON claims) "." b64url(HMAC-SHA256(key, first
//! part))`, both parts unpadded URL-safe base64. The claims bind the token to
//! a Cohort, a task, the claiming actor and the task's lease version, so a
//! token stops working as soon as the task is heartbeated, requeued or
//! reclaimed. The HMAC key is a 32-byte file, `cohort-lease.key`, in the
//! control plane's private state directory. Tokens are interchangeable with
//! the Go control plane.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use runeward_ledger::gojson;
use runeward_ledger::gotime;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::task::Task;

type HmacSha256 = Hmac<Sha256>;

/// The lease key's file name inside the state directory.
pub const LEASE_KEY_FILE_NAME: &str = "cohort-lease.key";

/// The lease key length in bytes.
pub const LEASE_KEY_LEN: usize = 32;

/// How long a lease token for a task without a lease deadline stays valid.
const NO_LEASE_VALIDITY_SECS: i64 = 24 * 60 * 60;

/// Decoder matching Go's `base64.RawURLEncoding`, which accepts non-zero
/// trailing bits.
const RAW_URL_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// The claims a lease token carries, in Go's field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseClaims {
    /// Format version; always 1.
    #[serde(rename = "v", default)]
    pub version: i64,
    /// The Cohort the task belongs to.
    #[serde(default)]
    pub cohort: String,
    /// The task ID.
    #[serde(default)]
    pub task: String,
    /// The actor holding the claim.
    #[serde(default)]
    pub actor: String,
    /// Expiry as Unix seconds; the token is invalid from this second on.
    #[serde(rename = "exp", default)]
    pub expires: i64,
    /// The task's lease version when the token was minted.
    #[serde(default)]
    pub lease: i64,
    /// 16 random bytes, unpadded URL-safe base64.
    #[serde(default)]
    pub nonce: String,
}

/// A lease token that is malformed, forged, bound to something else, or
/// expired. The message matches Go's `ErrInvalidLease`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cohort: invalid or expired task lease")]
pub struct InvalidLease;

/// A problem loading, creating or using the lease key.
#[derive(Debug, thiserror::Error)]
pub enum LeaseKeyError {
    /// No state directory was configured.
    #[error("cohort lease signing requires a state directory")]
    NoStateDir,
    /// The key file is readable by group or others.
    #[error("cohort lease key {0} must use 0600 permissions")]
    Permissions(String),
    /// The key file is not exactly 32 bytes.
    #[error("cohort lease key {0} has invalid length")]
    Length(String),
    /// A filesystem operation failed; the string says which.
    #[error("{0}: {1}")]
    Io(&'static str, #[source] io::Error),
    /// The system random source failed.
    #[error("{0}: {1}")]
    Random(&'static str, rand::Error),
    /// Encoding the claims failed.
    #[error("encode lease claims: {0}")]
    Encode(#[from] serde_json::Error),
}

/// Mints and verifies lease tokens with one HMAC key.
#[derive(Clone)]
pub struct LeaseSigner {
    key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for LeaseSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseSigner").finish_non_exhaustive()
    }
}

impl LeaseSigner {
    /// A signer using `key` as the HMAC key. Keys loaded from disk are always
    /// 32 bytes; any length is accepted here, as HMAC allows.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: Zeroizing::new(key.into()),
        }
    }

    /// Loads `cohort-lease.key` from `state_dir`, creating it (and the
    /// directory, 0700) with 32 random bytes and 0600 permissions when it
    /// does not exist. On Unix an existing key readable by group or others is
    /// rejected.
    pub fn load_or_create(state_dir: &Path) -> Result<Self, LeaseKeyError> {
        if state_dir.as_os_str().is_empty() {
            return Err(LeaseKeyError::NoStateDir);
        }
        let path = state_dir.join(LEASE_KEY_FILE_NAME);
        loop {
            match fs::read(&path) {
                Ok(key) => {
                    check_private(&path)?;
                    if key.len() != LEASE_KEY_LEN {
                        return Err(LeaseKeyError::Length(path.display().to_string()));
                    }
                    return Ok(Self::new(key));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(LeaseKeyError::Io("read cohort lease key", e)),
            }
            create_dir_private(state_dir)
                .map_err(|e| LeaseKeyError::Io("create cohort lease state directory", e))?;
            let mut key = Zeroizing::new(vec![0u8; LEASE_KEY_LEN]);
            rand::rngs::OsRng
                .try_fill_bytes(&mut key)
                .map_err(|e| LeaseKeyError::Random("generate cohort lease key", e))?;
            let mut f = match create_new_private(&path) {
                Ok(f) => f,
                // Lost a race with another creator: read theirs.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(LeaseKeyError::Io("create cohort lease key", e)),
            };
            if let Err(e) = f.write_all(&key) {
                drop(f);
                let _ = fs::remove_file(&path);
                return Err(LeaseKeyError::Io("write cohort lease key", e));
            }
            f.sync_all()
                .map_err(|e| LeaseKeyError::Io("sync cohort lease key", e))?;
            return Ok(Self {
                key: Zeroizing::new(key.to_vec()),
            });
        }
    }

    /// Mints a token for `task` as claimed in `cohort`, binding its ID, owner
    /// and lease version. It expires with the task's lease, or after 24 hours
    /// when the task has no lease deadline.
    pub fn issue(&self, cohort: &str, task: &Task) -> Result<String, LeaseKeyError> {
        let expires = match task.lease_expiry {
            Some(t) => t.timestamp(),
            None => gotime::now().timestamp() + NO_LEASE_VALIDITY_SECS,
        };
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| LeaseKeyError::Random("generate lease nonce", e))?;
        let claims = LeaseClaims {
            version: 1,
            cohort: cohort.to_owned(),
            task: task.id.clone(),
            actor: task.owner.clone(),
            expires,
            lease: task.lease_version,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
        };
        self.sign(&claims)
    }

    /// Signs arbitrary claims. [`issue`](Self::issue) is the normal entry
    /// point; this exists for tests and tooling.
    pub fn sign(&self, claims: &LeaseClaims) -> Result<String, LeaseKeyError> {
        let payload = gojson::marshal(claims)?;
        let body = URL_SAFE_NO_PAD.encode(payload);
        let sig = URL_SAFE_NO_PAD.encode(self.mac(body.as_bytes()));
        Ok(format!("{body}.{sig}"))
    }

    /// Verifies `token` for `cohort`, `task_id`, `actor` and the task's
    /// current `lease_version` at the current time.
    pub fn verify(
        &self,
        token: &str,
        cohort: &str,
        task_id: &str,
        actor: &str,
        lease_version: i64,
    ) -> Result<LeaseClaims, InvalidLease> {
        self.verify_at(
            token,
            cohort,
            task_id,
            actor,
            lease_version,
            gotime::now().timestamp(),
        )
    }

    /// Like [`verify`](Self::verify) with an explicit current time in Unix
    /// seconds.
    pub fn verify_at(
        &self,
        token: &str,
        cohort: &str,
        task_id: &str,
        actor: &str,
        lease_version: i64,
        now_unix: i64,
    ) -> Result<LeaseClaims, InvalidLease> {
        let mut parts = token.split('.');
        let (Some(body), Some(sig), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(InvalidLease);
        };
        if body.is_empty() || sig.is_empty() {
            return Err(InvalidLease);
        }
        let sig = decode_raw_url(sig)?;
        let mut mac = self.hmac();
        mac.update(body.as_bytes());
        mac.verify_slice(&sig).map_err(|_| InvalidLease)?;
        let payload = decode_raw_url(body)?;
        let claims: LeaseClaims = serde_json::from_slice(&payload).map_err(|_| InvalidLease)?;
        if claims.version != 1
            || claims.cohort != cohort
            || claims.task != task_id
            || claims.actor != actor
            || claims.lease != lease_version
            || claims.nonce.is_empty()
            || now_unix >= claims.expires
        {
            return Err(InvalidLease);
        }
        Ok(claims)
    }

    fn hmac(&self) -> HmacSha256 {
        // HMAC accepts keys of any length, so this cannot fail.
        <HmacSha256 as Mac>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"))
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut mac = self.hmac();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

/// Decodes unpadded URL-safe base64 like Go's `RawURLEncoding`, which skips
/// CR and LF.
fn decode_raw_url(s: &str) -> Result<Vec<u8>, InvalidLease> {
    let cleaned: String = s.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    RAW_URL_LENIENT.decode(cleaned).map_err(|_| InvalidLease)
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), LeaseKeyError> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        return Err(LeaseKeyError::Permissions(path.display().to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), LeaseKeyError> {
    Ok(())
}

#[cfg(unix)]
fn create_dir_private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_dir_private(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn create_new_private(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_private(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}
