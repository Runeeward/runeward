//! Charter resolution, parsing and signed-Charter enforcement.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::schema::Charter;
use crate::signature::{Signature, SignatureError};
use crate::validate::ValidationError;

/// Extensions in resolution order: within one directory the earliest wins, so
/// `foo.toml` shadows `foo.yaml`.
pub const CHARTER_EXTENSIONS: [&str; 4] = [".toml", ".yaml", ".yml", ".json"];

/// Environment switch that makes every load require a detached signature.
pub const REQUIRE_SIGNED_ENV: &str = "RUNEWARD_REQUIRE_SIGNED_PROFILES";
/// Environment variable holding the verify key (base64 material or a path).
pub const VERIFY_KEY_ENV: &str = "RUNEWARD_PROFILE_VERIFY_KEY";

/// Whether loads must carry a valid detached signature.
///
/// The Go loader reads this from the environment on every load; the explicit
/// variants exist so callers (and tests) need not mutate process state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SignedCharters {
    /// Consult [`REQUIRE_SIGNED_ENV`] and [`VERIFY_KEY_ENV`] at load time.
    #[default]
    FromEnv,
    /// Never require a signature.
    Disabled,
    /// Require a signature verifying against this key (base64 material or a
    /// path to a file holding it). An empty key fails every load.
    Required { verify_key: String },
}

impl SignedCharters {
    /// Resolves the policy from an environment lookup, as the Go loader does.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let enabled = lookup(REQUIRE_SIGNED_ENV)
            .map(|v| v.trim().to_lowercase())
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        if !enabled {
            return Self::Disabled;
        }
        Self::Required {
            verify_key: lookup(VERIFY_KEY_ENV).unwrap_or_default(),
        }
    }

    fn resolve(&self) -> Self {
        match self {
            Self::FromEnv => Self::from_lookup(|k| std::env::var(k).ok()),
            other => other.clone(),
        }
    }
}

/// Controls where Charters are resolved from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// When set, pins the search to this single directory.
    pub config_dir: Option<PathBuf>,
    /// Resolves project-local Charters; defaults to the process cwd.
    pub working_dir: Option<PathBuf>,
    /// Signed-Charter enforcement; defaults to the environment.
    pub signed: SignedCharters,
}

/// Loading a Charter failed.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("empty profile name")]
    EmptyName,
    #[error("invalid profile name {0:?}")]
    InvalidName(String),
    #[error("profile not found: {name:?} (searched {})", join_paths(.searched))]
    NotFound {
        name: String,
        searched: Vec<PathBuf>,
    },
    #[error("read profile {path:?}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("parse profile {path:?}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("invalid profile {path:?}: {source}")]
    Invalid {
        path: PathBuf,
        source: ValidationError,
    },
    #[error("invalid profile {path:?}: {source}")]
    Signature {
        path: PathBuf,
        source: SignatureFailure,
    },
}

/// Why signed-Charter enforcement rejected a file.
#[derive(Debug, thiserror::Error)]
pub enum SignatureFailure {
    #[error("signed profile enforcement is enabled but {VERIFY_KEY_ENV} is unset")]
    KeyUnset,
    #[error("decode verify key from {VERIFY_KEY_ENV}: {0}")]
    DecodeKey(#[source] runeward_keys::KeyError),
    #[error("required detached signature {path:?}: {source}")]
    Missing { path: PathBuf, source: io::Error },
    #[error("parse detached signature: {0}")]
    Parse(#[source] SignatureError),
    #[error("verify detached signature: {0}")]
    Verify(#[source] SignatureError),
}

fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolves and parses the named Charter; the extension selects the parser.
///
/// Resolution order (first match wins):
///  1. `<working_dir>/.runeward/<name>.{toml,yaml,yml,json}`
///  2. `$XDG_CONFIG_HOME/runeward/…` or `~/.config/runeward/…`
///
/// With [`Options::config_dir`] set only that directory is consulted.
pub fn load(name: &str, opts: &Options) -> Result<Charter, LoadError> {
    validate_name(name)?;
    let dirs = search_dirs(opts, |k| std::env::var(k).ok());
    for dir in &dirs {
        for ext in CHARTER_EXTENSIONS {
            let path = dir.join(format!("{name}{ext}"));
            if fs::metadata(&path).is_ok() {
                return parse_file(&path, name, &opts.signed);
            }
        }
    }
    Err(LoadError::NotFound {
        name: name.to_owned(),
        searched: dirs,
    })
}

/// Returns the names of every Charter on the search path, sorted and
/// de-duplicated (earlier tiers shadow later ones). Missing directories are
/// skipped.
pub fn list(opts: &Options) -> Vec<String> {
    let mut names = BTreeSet::new();
    for dir in search_dirs(opts, |k| std::env::var(k).ok()) {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if let Some(stem) = charter_stem(file_name) {
                names.insert(stem.to_owned());
            }
        }
    }
    names.into_iter().collect()
}

/// Strips a Charter extension using Go's `filepath.Ext` rule (the suffix from
/// the final dot), so `.toml` alone yields an empty name exactly as in Go.
fn charter_stem(file_name: &str) -> Option<&str> {
    let dot = file_name.rfind('.')?;
    CHARTER_EXTENSIONS
        .contains(&&file_name[dot..])
        .then(|| &file_name[..dot])
}

/// Returns the ordered directories to consult.
fn search_dirs(opts: &Options, lookup: impl Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    if let Some(dir) = opts
        .config_dir
        .as_ref()
        .filter(|d| !d.as_os_str().is_empty())
    {
        return vec![dir.clone()];
    }
    let wd = opts
        .working_dir
        .clone()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let mut dirs = vec![wd.join(".runeward")];
    if let Some(xdg) = lookup("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        dirs.push(Path::new(&xdg).join("runeward"));
    } else if let Some(home) = home_dir(&lookup) {
        dirs.push(home.join(".config").join("runeward"));
    }
    dirs
}

/// The user's home directory as Go's `os.UserHomeDir` finds it.
pub(crate) fn home_dir(lookup: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    lookup(var).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn validate_name(name: &str) -> Result<(), LoadError> {
    if name.is_empty() {
        return Err(LoadError::EmptyName);
    }
    // Guard against path traversal in Charter names.
    if name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(LoadError::InvalidName(name.to_owned()));
    }
    Ok(())
}

/// Parses, defaults and validates a Charter file at a known path.
///
/// `name` becomes [`Charter::name`]; signature enforcement runs over the raw
/// bytes before anything is decoded.
pub fn parse_file(path: &Path, name: &str, signed: &SignedCharters) -> Result<Charter, LoadError> {
    let data = fs::read(path).map_err(|source| LoadError::Read {
        path: path.to_owned(),
        source,
    })?;
    verify_signature(path, &data, signed).map_err(|source| LoadError::Signature {
        path: path.to_owned(),
        source,
    })?;
    let is_toml = path.extension().is_some_and(|e| e == "toml");
    let mut charter = parse_bytes(&data, is_toml).map_err(|message| LoadError::Parse {
        path: path.to_owned(),
        message,
    })?;
    charter.name = name.to_owned();
    charter.source = path.to_owned();
    charter.apply_defaults();
    charter.validate().map_err(|source| LoadError::Invalid {
        path: path.to_owned(),
        source,
    })?;
    Ok(charter)
}

/// Strictly decodes Charter bytes: TOML when `is_toml`, otherwise YAML (which
/// also covers JSON, as in Go). No defaults or validation are applied.
pub fn parse_bytes(data: &[u8], is_toml: bool) -> Result<Charter, String> {
    if is_toml {
        let text = std::str::from_utf8(data).map_err(|e| format!("toml: {e}"))?;
        return toml::from_str(text).map_err(|e| e.to_string().trim_end().to_owned());
    }
    let mut value: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(data).map_err(|e| e.to_string())?;
    value.apply_merge().map_err(|e| e.to_string())?;
    // Go decodes YAML through JSON, where an empty document or an explicit
    // null leaves the target at its zero value; drop nulls to match.
    strip_nulls(&mut value);
    if value.is_null() {
        return Ok(Charter::default());
    }
    serde_yaml_ng::from_value(value).map_err(|e| e.to_string())
}

fn strip_nulls(value: &mut serde_yaml_ng::Value) {
    match value {
        serde_yaml_ng::Value::Mapping(map) => {
            map.retain(|_, v| !v.is_null());
            for (_, v) in map.iter_mut() {
                strip_nulls(v);
            }
        }
        serde_yaml_ng::Value::Sequence(seq) => seq.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

fn verify_signature(
    path: &Path,
    content: &[u8],
    signed: &SignedCharters,
) -> Result<(), SignatureFailure> {
    let SignedCharters::Required { verify_key } = signed.resolve() else {
        return Ok(());
    };
    let verify_key = verify_key.trim();
    if verify_key.is_empty() {
        return Err(SignatureFailure::KeyUnset);
    }
    // The setting may be key material or a path to a file holding it.
    let material = fs::read_to_string(verify_key)
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| verify_key.to_owned());
    let public = runeward_keys::decode_public(&material).map_err(SignatureFailure::DecodeKey)?;

    let mut sig_path = path.as_os_str().to_owned();
    sig_path.push(".sig");
    let sig_path = PathBuf::from(sig_path);
    let raw = fs::read(&sig_path).map_err(|source| SignatureFailure::Missing {
        path: sig_path,
        source,
    })?;
    let sig = Signature::parse(&raw).map_err(SignatureFailure::Parse)?;
    sig.verify(content, &public)
        .map_err(SignatureFailure::Verify)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).expect("write");
        path
    }

    fn opts(dir: &Path, signed: SignedCharters) -> Options {
        Options {
            config_dir: Some(dir.to_owned()),
            signed,
            ..Options::default()
        }
    }

    #[test]
    fn signed_default_behaviour_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "p.toml", "host.image = \"img\"\n");
        let p = load("p", &opts(dir.path(), SignedCharters::Disabled)).expect("load");
        assert_eq!(p.name, "p");
        assert_eq!(p.host.image, "img");
    }

    #[test]
    fn signed_requires_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let content = "host.image = \"img\"\n";
        let path = write(dir.path(), "p.toml", content);
        let key = SigningKey::from_bytes(&[9; 32]);
        fs::write(
            path.with_extension("toml.sig"),
            Signature::new(content.as_bytes(), &key).marshal(),
        )
        .expect("write sig");

        let unset = SignedCharters::Required {
            verify_key: String::new(),
        };
        let err = load("p", &opts(dir.path(), unset)).expect_err("must fail");
        assert!(matches!(
            err,
            LoadError::Signature {
                source: SignatureFailure::KeyUnset,
                ..
            }
        ));
        assert!(err.to_string().contains(VERIFY_KEY_ENV));

        let encoded = runeward_keys::encode_public(&key.verifying_key());
        let with_key = SignedCharters::Required {
            verify_key: encoded.clone(),
        };
        load("p", &opts(dir.path(), with_key)).expect("signed load");

        // A path to a key file works too.
        let key_file = write(dir.path(), "charter.pub", &format!("{encoded}\n"));
        let from_file = SignedCharters::Required {
            verify_key: key_file.display().to_string(),
        };
        load("p", &opts(dir.path(), from_file)).expect("signed load via key file");
    }

    #[test]
    fn signed_rejects_missing_or_invalid_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(dir.path(), "p.toml", "host.image = \"img\"\n");
        let key = SigningKey::from_bytes(&[5; 32]);
        let signed = SignedCharters::Required {
            verify_key: runeward_keys::encode_public(&key.verifying_key()),
        };
        let o = opts(dir.path(), signed);
        assert!(matches!(
            load("p", &o),
            Err(LoadError::Signature {
                source: SignatureFailure::Missing { .. },
                ..
            })
        ));
        fs::write(
            path.with_extension("toml.sig"),
            r#"{"format":"runeward.profile.sig.v1","key_id":"abcd","sig":"bogus"}"#,
        )
        .expect("write sig");
        assert!(load("p", &o).is_err());
    }

    #[test]
    fn signed_policy_from_lookup() {
        let env = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            SignedCharters::from_lookup(move |k| map.get(k).cloned())
        };
        assert_eq!(env(&[]), SignedCharters::Disabled);
        assert_eq!(env(&[(REQUIRE_SIGNED_ENV, "0")]), SignedCharters::Disabled);
        for on in ["1", "true", " YES ", "On"] {
            assert_eq!(
                env(&[(REQUIRE_SIGNED_ENV, on), (VERIFY_KEY_ENV, "k")]),
                SignedCharters::Required {
                    verify_key: "k".into()
                }
            );
        }
    }

    #[test]
    fn resolution_order_and_shadowing() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "a.yaml", "host:\n  image: from-yaml\n");
        write(dir.path(), "a.toml", "[host]\nimage = \"from-toml\"\n");
        write(dir.path(), "b.json", r#"{"host": {"image": "from-json"}}"#);
        write(dir.path(), "c.yml", "host:\n  image:\n");
        write(dir.path(), "notes.txt", "");
        fs::create_dir(dir.path().join("d.toml")).expect("mkdir");
        let o = opts(dir.path(), SignedCharters::Disabled);
        assert_eq!(load("a", &o).expect("a").host.image, "from-toml");
        assert_eq!(load("b", &o).expect("b").host.image, "from-json");
        // An explicit YAML null keeps the zero value, so the default applies.
        assert_eq!(
            load("c", &o).expect("c").host.image,
            "ghcr.io/runeeward/runeward-sandbox:latest"
        );
        assert_eq!(list(&o), ["a", "b", "c"]);
        assert!(matches!(load("zzz", &o), Err(LoadError::NotFound { .. })));
        assert!(matches!(load("../a", &o), Err(LoadError::InvalidName(_))));
        assert!(matches!(load("", &o), Err(LoadError::EmptyName)));
    }

    #[test]
    fn search_dirs_follow_xdg_then_home() {
        let o = Options {
            working_dir: Some("/w".into()),
            ..Options::default()
        };
        let xdg = search_dirs(&o, |k| (k == "XDG_CONFIG_HOME").then(|| "/x".into()));
        assert_eq!(xdg, [PathBuf::from("/w/.runeward"), "/x/runeward".into()]);
        let home = search_dirs(&o, |k| {
            matches!(k, "HOME" | "USERPROFILE").then(|| "/h".into())
        });
        assert_eq!(
            home,
            [PathBuf::from("/w/.runeward"), "/h/.config/runeward".into()]
        );
        let pinned = Options {
            config_dir: Some("/c".into()),
            ..o
        };
        assert_eq!(search_dirs(&pinned, |_| None), [PathBuf::from("/c")]);
    }

    #[test]
    fn unknown_fields_are_rejected_in_every_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(dir.path(), "t.toml", "[host]\nimgae = \"x\"\n");
        write(dir.path(), "y.yaml", "host:\n  imgae: x\n");
        write(dir.path(), "j.json", r#"{"bogus": 1}"#);
        let o = opts(dir.path(), SignedCharters::Disabled);
        for name in ["t", "y", "j"] {
            let err = load(name, &o).expect_err("must fail");
            assert!(matches!(err, LoadError::Parse { .. }), "{name}: {err}");
        }
    }

    #[test]
    fn validation_errors_name_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "p.toml",
            "[[policy]]\ntool = \"shell\"\nverdict = \"maybe\"\n",
        );
        let err = load("p", &opts(dir.path(), SignedCharters::Disabled)).expect_err("must fail");
        let msg = err.to_string();
        assert!(msg.starts_with("invalid profile \""), "{msg}");
        assert!(
            msg.ends_with(r#"p.toml": policy[0]: invalid verdict "maybe""#),
            "{msg}"
        );
    }
}
