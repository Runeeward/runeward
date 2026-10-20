//! The Runeward client login store, kept separately from server-side authz
//! configuration. Rust port of the Go `internal/credentials` package.
//!
//! The login lives in one JSON file, by default
//! `<user config dir>/runeward/credentials.json` (`$XDG_CONFIG_HOME` or
//! `~/.config` on Linux and other Unix systems, `~/Library/Application
//! Support` on macOS, `%AppData%` on Windows, as Go's `os.UserConfigDir`),
//! or the path in `RUNEWARD_CREDENTIALS_FILE`. The file is written
//! atomically with 0600 permissions, and on Unix a file readable by group or
//! others is refused. Its JSON is byte-identical to what the Go CLI writes.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use runeward_ledger::gojson;
use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The environment variable that overrides the credentials file path.
pub const ENV_FILE: &str = "RUNEWARD_CREDENTIALS_FILE";

/// A stored client login.
///
/// The JSON matches Go's `credentials.Login`: `issuer`, `client_id` and
/// `audience` are omitted when empty, and `expires_at` is always written
/// (as `0001-01-01T00:00:00Z` when unset, because Go's `omitempty` never
/// omits a time).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Login {
    /// The bearer credential.
    #[serde(default, deserialize_with = "nullable")]
    pub token: String,
    /// The OIDC issuer the token came from.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub issuer: String,
    /// The OIDC client ID used to obtain the token.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub client_id: String,
    /// The audience the token was requested for.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub audience: String,
    /// When the token expires; `None` means it does not.
    #[serde(default, serialize_with = "ser_time", deserialize_with = "de_time")]
    pub expires_at: Option<Time>,
}

impl Login {
    /// A login holding just `token`.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            ..Self::default()
        }
    }

    /// Reports whether the login has an expiry at or before `now`.
    pub fn is_expired_at(&self, now: &Time) -> bool {
        self.expires_at.is_some_and(|exp| *now > exp)
    }
}

fn nullable<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

fn ser_time<S: Serializer>(t: &Option<Time>, s: S) -> Result<S::Ok, S::Error> {
    let t = t.unwrap_or_else(gotime::zero);
    s.serialize_str(&gotime::format_rfc3339_nano(&t))
}

fn de_time<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Time>, D::Error> {
    let Some(s) = Option::<String>::deserialize(d)? else {
        return Ok(None);
    };
    let t = gotime::parse_rfc3339(&s).map_err(serde::de::Error::custom)?;
    Ok((!gotime::is_zero(&t)).then_some(t))
}

/// A credentials store problem.
#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    /// Reading, writing or removing the file failed. A missing file is
    /// reported here with [`io::ErrorKind::NotFound`]; see
    /// [`is_not_found`](Self::is_not_found).
    #[error(transparent)]
    Io(#[from] io::Error),
    /// No credentials path could be determined.
    #[error("{0}")]
    NoPath(&'static str),
    /// The file is readable by group or others.
    #[error("credentials file {0} must use 0600 permissions")]
    Permissions(String),
    /// The file is not valid JSON for a [`Login`].
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The stored token is blank.
    #[error("stored Runeward credential is empty")]
    EmptyStored,
    /// [`Store::save`] was given a blank token.
    #[error("cannot save an empty Runeward credential")]
    EmptySave,
}

impl CredentialsError {
    /// Reports whether the credentials file does not exist.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(e) if e.kind() == io::ErrorKind::NotFound)
    }
}

/// The credentials file at one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    /// A store at an explicit path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The store at [`path()`].
    pub fn from_env() -> Result<Self, CredentialsError> {
        path().map(Self::at)
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the stored login. Fails when the file is missing (see
    /// [`CredentialsError::is_not_found`]), too permissive, malformed, or
    /// holds a blank token.
    pub fn load(&self) -> Result<Login, CredentialsError> {
        check_private(&self.path)?;
        let data = fs::read(&self.path)?;
        let login: Login = serde_json::from_slice(&data)?;
        if login.token.trim().is_empty() {
            return Err(CredentialsError::EmptyStored);
        }
        Ok(login)
    }

    /// The stored token, or an empty string when there is no usable login
    /// (missing, unreadable or expired).
    pub fn load_token(&self) -> String {
        match self.load() {
            Ok(login) if !login.is_expired_at(&gotime::now()) => login.token,
            _ => String::new(),
        }
    }

    /// Writes `login` (token trimmed) atomically with 0600 permissions,
    /// creating the parent directory (0700) as needed.
    pub fn save(&self, mut login: Login) -> Result<(), CredentialsError> {
        login.token = login.token.trim().to_owned();
        if login.token.is_empty() {
            return Err(CredentialsError::EmptySave);
        }
        let dir = match self.path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        create_dir_private(&dir)?;
        // json.MarshalIndent output: no trailing newline.
        let mut data = gojson::marshal_indent(&login)?;
        data.pop();
        // tempfile creates the file with 0600 on Unix.
        let mut tmp = tempfile::Builder::new()
            .prefix(".credentials-")
            .tempfile_in(&dir)?;
        set_private(tmp.as_file())?;
        tmp.write_all(&data)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.path).map_err(|e| e.error)?;
        if let Ok(d) = fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Removes the stored login; a missing file is not an error.
    pub fn delete(&self) -> Result<(), CredentialsError> {
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

/// The credentials file path: `RUNEWARD_CREDENTIALS_FILE` (trimmed) when
/// set, otherwise `runeward/credentials.json` under the user config
/// directory.
pub fn path() -> Result<PathBuf, CredentialsError> {
    if let Some(p) = env::var_os(ENV_FILE) {
        let s = p.to_string_lossy();
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    Ok(user_config_dir()?.join("runeward").join("credentials.json"))
}

/// Reads the login at [`path()`]; see [`Store::load`].
pub fn load() -> Result<Login, CredentialsError> {
    Store::from_env()?.load()
}

/// The usable token at [`path()`], or an empty string; see
/// [`Store::load_token`].
pub fn load_token() -> String {
    Store::from_env()
        .map(|s| s.load_token())
        .unwrap_or_default()
}

/// Writes the login to [`path()`]; see [`Store::save`].
pub fn save(login: Login) -> Result<(), CredentialsError> {
    Store::from_env()?.save(login)
}

/// Removes the login at [`path()`]; see [`Store::delete`].
pub fn delete() -> Result<(), CredentialsError> {
    Store::from_env()?.delete()
}

/// Go's `os.UserConfigDir`.
fn user_config_dir() -> Result<PathBuf, CredentialsError> {
    let var = |k: &str| env::var_os(k).filter(|v| !v.is_empty());
    if cfg!(windows) {
        return var("AppData")
            .map(PathBuf::from)
            .ok_or(CredentialsError::NoPath("%AppData% is not defined"));
    }
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        return var("HOME")
            .map(|h| PathBuf::from(h).join("Library/Application Support"))
            .ok_or(CredentialsError::NoPath("$HOME is not defined"));
    }
    match var("XDG_CONFIG_HOME") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if dir.is_absolute() {
                Ok(dir)
            } else {
                Err(CredentialsError::NoPath(
                    "path in $XDG_CONFIG_HOME is relative",
                ))
            }
        }
        None => {
            var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .ok_or(CredentialsError::NoPath(
                    "neither $XDG_CONFIG_HOME nor $HOME are defined",
                ))
        }
    }
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), CredentialsError> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        return Err(CredentialsError::Permissions(path.display().to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), CredentialsError> {
    Ok(())
}

#[cfg(unix)]
fn set_private(f: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private(_f: &fs::File) -> io::Result<()> {
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
