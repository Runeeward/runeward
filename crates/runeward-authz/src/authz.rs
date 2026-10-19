//! Principals, the principals file and the token [`Store`].

use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::oidc::OidcVerifier;
use crate::pathmatch::path_match;
use crate::{Error, decode_first_value};

/// Environment variable that points at the RBAC principals file.
pub const ENV_FILE: &str = "RUNEWARD_AUTHZ_FILE";

/// A named identity that authenticates with a bearer token and carries its
/// own authorization scope.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawPrincipal")]
pub struct Principal {
    /// Human-readable identity used as the audit actor.
    pub name: String,
    /// Ownership boundary shared by principals that may collaborate on the
    /// same Citadels, Cohorts, snapshots, and runs. Empty falls back to
    /// `name` (one principal per tenant).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tenant: String,
    /// Bearer token that authenticates this principal.
    pub token: String,
    /// Glob patterns (Go `path.Match` syntax) matched against a profile name.
    /// An empty list for a non-admin principal means it may launch nothing; a
    /// list containing `*` allows every profile.
    pub allowed_profiles: Vec<String>,
    /// Permits the principal to approve or deny pending actions.
    pub can_approve: bool,
    /// Optionally limits approval visibility and decisions to actions from
    /// matching profiles. Empty keeps global reviewer behaviour.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub approval_profiles: Vec<String>,
    /// Bypasses all profile restrictions and implies approval rights.
    pub admin: bool,
}

/// The on-disk shape of a principal. Every field may be absent or `null`, and
/// unknown fields are rejected, as Go's decoder with `DisallowUnknownFields`
/// does.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
struct RawPrincipal {
    name: Option<String>,
    tenant: Option<String>,
    token: Option<String>,
    allowed_profiles: Option<Vec<String>>,
    can_approve: Option<bool>,
    approval_profiles: Option<Vec<String>>,
    admin: Option<bool>,
}

impl From<RawPrincipal> for Principal {
    fn from(raw: RawPrincipal) -> Self {
        Self {
            name: raw.name.unwrap_or_default(),
            tenant: raw.tenant.unwrap_or_default(),
            token: raw.token.unwrap_or_default(),
            allowed_profiles: raw.allowed_profiles.unwrap_or_default(),
            can_approve: raw.can_approve.unwrap_or_default(),
            approval_profiles: raw.approval_profiles.unwrap_or_default(),
            admin: raw.admin.unwrap_or_default(),
        }
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Principal")
            .field("name", &self.name)
            .field("tenant", &self.tenant)
            .field(
                "token",
                &if self.token.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .field("allowed_profiles", &self.allowed_profiles)
            .field("can_approve", &self.can_approve)
            .field("approval_profiles", &self.approval_profiles)
            .field("admin", &self.admin)
            .finish()
    }
}

/// Whether any of `patterns` matches `profile`. A malformed pattern never
/// matches.
fn any_match(patterns: &[String], profile: &str) -> bool {
    patterns
        .iter()
        .any(|p| p == "*" || path_match(p, profile).unwrap_or(false))
}

impl Principal {
    /// The stable resource-ownership boundary for the principal: the trimmed
    /// tenant, or the name when no tenant is set.
    pub fn tenant_id(&self) -> &str {
        match self.tenant.trim() {
            "" => &self.name,
            tenant => tenant,
        }
    }

    /// Whether the principal may launch the named profile. Admins bypass all
    /// restrictions; others need a matching `allowed_profiles` pattern.
    pub fn can_launch(&self, profile: &str) -> bool {
        self.admin || any_match(&self.allowed_profiles, profile)
    }

    /// Whether the principal may approve or deny actions.
    pub fn may_approve(&self) -> bool {
        self.admin || self.can_approve
    }

    /// Whether the principal may review an action from `profile`. Admins may
    /// review everything; an approver with no `approval_profiles` remains a
    /// global reviewer.
    pub fn can_approve_profile(&self, profile: &str) -> bool {
        if !self.may_approve() {
            return false;
        }
        self.admin
            || self.approval_profiles.is_empty()
            || any_match(&self.approval_profiles, profile)
    }

    /// Whether the principal may launch any profile at all: admins always may,
    /// others when they have at least one non-blank allowed-profile pattern.
    pub fn may_launch(&self) -> bool {
        self.admin || self.allowed_profiles.iter().any(|p| !p.trim().is_empty())
    }
}

/// Principals indexed by token, plus an optional OIDC verifier. Safe for
/// concurrent use.
pub struct Store {
    principals: Vec<Arc<Principal>>,
    token_hashes: Vec<[u8; 32]>,
    oidc: Option<OidcVerifier>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("principals", &self.principals)
            .field("oidc", &self.oidc)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Reads a JSON principals file of the form
    /// `{"principals": [ {"name": "...", "token": "...", ...}, ... ]}`.
    ///
    /// On Unix the file must not be group- or world-accessible. Entries with
    /// empty names, empty tokens, duplicate names or duplicate tokens are
    /// rejected, as are unknown fields.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        check_permissions(path)?;
        let data = std::fs::read(path)
            .map_err(|e| Error::Config(format!("authz: read {}: {e}", path.display())))?;
        let parse_err = |e: String| Error::Config(format!("authz: parse {}: {e}", path.display()));
        let value = decode_first_value(&data).map_err(parse_err)?;
        let principals = parse_store_file(value).map_err(parse_err)?;
        Self::build(principals)
    }

    /// Builds a store from in-memory principals, applying the same validation
    /// as [`Store::load`].
    pub fn from_principals(principals: Vec<Principal>) -> Result<Self, Error> {
        Self::build(principals.into_iter().map(Some).collect())
    }

    fn build(principals: Vec<Option<Principal>>) -> Result<Self, Error> {
        let mut store = Self {
            principals: Vec::with_capacity(principals.len()),
            token_hashes: Vec::with_capacity(principals.len()),
            oidc: None,
        };
        let mut names = HashSet::with_capacity(principals.len());
        let mut tokens = HashSet::with_capacity(principals.len());
        for (i, p) in principals.into_iter().enumerate() {
            let Some(mut p) = p else {
                return Err(Error::Config(format!(
                    "authz: principal at index {i} is null"
                )));
            };
            p.name = p.name.trim().to_owned();
            p.tenant = p.tenant.trim().to_owned();
            if p.name.is_empty() {
                return Err(Error::Config(format!(
                    "authz: principal at index {i} has empty name"
                )));
            }
            if !names.insert(p.name.clone()) {
                return Err(Error::Config(format!(
                    "authz: duplicate principal name {:?}",
                    p.name
                )));
            }
            if p.token.is_empty() {
                return Err(Error::Config(format!(
                    "authz: principal {:?} has empty token",
                    p.name
                )));
            }
            if !tokens.insert(p.token.clone()) {
                return Err(Error::Config(format!(
                    "authz: duplicate token for principal {:?}",
                    p.name
                )));
            }
            store
                .token_hashes
                .push(Sha256::digest(p.token.as_bytes()).into());
            store.principals.push(Arc::new(p));
        }
        Ok(store)
    }

    /// Builds a store from the file named by `RUNEWARD_AUTHZ_FILE` and the
    /// OIDC settings in `RUNEWARD_OIDC_*`.
    ///
    /// Returns `Ok(None)` when neither is configured, signalling that RBAC is
    /// not configured and the caller should fall back to legacy single-token
    /// auth. With OIDC but no file, the store has no static principals.
    pub async fn from_env() -> Result<Option<Self>, Error> {
        let path = std::env::var(ENV_FILE).unwrap_or_default();
        let path = path.trim();
        let mut store = if path.is_empty() {
            Self::build(Vec::new())?
        } else {
            Self::load(path)?
        };
        let verifier = OidcVerifier::from_env().await?;
        let configured = verifier.is_some();
        store.oidc = verifier;
        if path.is_empty() && !configured {
            return Ok(None);
        }
        Ok(Some(store))
    }

    /// Returns the principal that owns `token`, or `None` when the token is
    /// empty or unknown. Static tokens are compared in constant time (over
    /// their SHA-256 digests, against every principal); on a miss, a
    /// configured OIDC verifier is tried.
    pub async fn identify(&self, token: &str) -> Option<Arc<Principal>> {
        if token.is_empty() {
            return None;
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found = None;
        for (i, stored) in self.token_hashes.iter().enumerate() {
            if bool::from(stored.ct_eq(&hash)) {
                found = Some(i);
            }
        }
        if let Some(i) = found {
            return Some(self.principals[i].clone());
        }
        match &self.oidc {
            Some(oidc) => oidc.verify(token).await.ok().map(Arc::new),
            None => None,
        }
    }

    /// The number of configured static principals.
    pub fn len(&self) -> usize {
        self.principals.len()
    }

    /// Whether there are no static principals.
    pub fn is_empty(&self) -> bool {
        self.principals.is_empty()
    }

    /// The configured static principals, in file order.
    pub fn principals(&self) -> &[Arc<Principal>] {
        &self.principals
    }

    /// The OIDC verifier, when OIDC is configured.
    pub fn oidc(&self) -> Option<&OidcVerifier> {
        self.oidc.as_ref()
    }

    /// Rejects credentials that are too short for an exposed control plane:
    /// any non-loopback listener requires tokens of at least 32 bytes.
    pub fn validate_for_network(&self) -> Result<(), Error> {
        for p in &self.principals {
            if p.token.len() < 32 {
                return Err(Error::Config(format!(
                    "authz: principal {:?} token is too short for network use; require at least 32 characters",
                    p.name
                )));
            }
        }
        Ok(())
    }
}

/// Rejects a principals file readable or writable by group or others. Errors
/// reading metadata are left for the subsequent read to report.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let perm = meta.permissions().mode() & 0o777;
        if perm & 0o077 != 0 {
            return Err(Error::Config(format!(
                "authz: {} permissions {perm:04o} expose bearer tokens; use 0600",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), Error> {
    Ok(())
}

/// Extracts the principal entries from a decoded principals file. Objects are
/// required where Go decodes into structs (serde would otherwise also accept
/// positional arrays); `null` decodes to the zero value.
fn parse_store_file(value: Value) -> Result<Vec<Option<Principal>>, String> {
    let mut file = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Object(map) => map,
        other => return Err(format!("cannot unmarshal {} into store file", kind(&other))),
    };
    if let Some(unknown) = file.keys().find(|k| *k != "principals") {
        return Err(format!("json: unknown field {unknown:?}"));
    }
    let entries = match file.remove("principals") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(entries)) => entries,
        Some(other) => {
            return Err(format!(
                "cannot unmarshal {} into field principals",
                kind(&other)
            ));
        }
    };
    entries
        .into_iter()
        .enumerate()
        .map(|(i, entry)| match entry {
            Value::Null => Ok(None),
            Value::Object(_) => serde_json::from_value::<Principal>(entry)
                .map(Some)
                .map_err(|e| format!("principals[{i}]: {e}")),
            other => Err(format!(
                "cannot unmarshal {} into principal at index {i}",
                kind(&other)
            )),
        })
        .collect()
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{child_test_name, is_child, run_child};
    use std::io::Write;
    use std::path::PathBuf;

    fn write_file(dir: &tempfile::TempDir, contents: &str) -> PathBuf {
        let path = dir.path().join("authz.json");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).expect("create temp file");
        f.write_all(contents.as_bytes()).expect("write temp file");
        path
    }

    fn load(contents: &str) -> Result<Store, Error> {
        let dir = tempfile::tempdir().expect("tempdir");
        Store::load(write_file(&dir, contents))
    }

    fn p() -> Principal {
        Principal::default()
    }

    fn profiles(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[tokio::test]
    async fn load_valid() {
        let s = load(
            r#"{
                "principals": [
                    {"name": "root", "token": "tok-admin", "admin": true},
                    {"name": "reviewer", "token": "tok-rev", "can_approve": true, "allowed_profiles": ["team-*"]},
                    {"name": "dev", "token": "tok-dev", "allowed_profiles": ["build", "test-*"]}
                ]
            }"#,
        )
        .expect("load");
        assert_eq!(s.len(), 3);
        assert!(s.identify("tok-admin").await.is_some());
    }

    #[test]
    fn load_duplicate_token() {
        assert!(
            load(
                r#"{"principals": [{"name": "a", "token": "dup"}, {"name": "b", "token": "dup"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn load_duplicate_name() {
        assert!(
            load(r#"{"principals":[{"name":"same","token":"one"},{"name":"same","token":"two"}]}"#)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_exposed_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, r#"{"principals":[{"name":"a","token":"one"}]}"#);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = Store::load(&path).expect_err("insecure permissions");
        assert!(err.to_string().contains("permissions 0644"), "{err}");
    }

    #[test]
    fn load_empty_token() {
        assert!(load(r#"{"principals": [{"name": "a", "token": ""}]}"#).is_err());
    }

    #[test]
    fn load_empty_name() {
        assert!(load(r#"{"principals": [{"name": "  ", "token": "t"}]}"#).is_err());
    }

    #[test]
    fn load_null_principal() {
        let err = load(r#"{"principals": [null]}"#).expect_err("null entry");
        assert!(err.to_string().contains("index 0 is null"), "{err}");
    }

    #[test]
    fn load_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(Store::load(dir.path().join("nope.json")).is_err());
    }

    #[test]
    fn load_bad_json() {
        assert!(load(r#"{"principals": ["#).is_err());
    }

    #[test]
    fn load_unknown_field() {
        assert!(load(r#"{"principals": [{"name": "a", "token": "t", "bogus": 1}]}"#).is_err());
        assert!(load(r#"{"principals": [], "bogus": 1}"#).is_err());
    }

    #[test]
    fn load_rejects_positional_principal() {
        assert!(load(r#"{"principals": [["a", "", "t"]]}"#).is_err());
    }

    #[test]
    fn load_trims_name_and_tenant() {
        let s = load(r#"{"principals": [{"name": " a ", "tenant": " t ", "token": "x"}]}"#)
            .expect("load");
        assert_eq!(s.principals()[0].name, "a");
        assert_eq!(s.principals()[0].tenant, "t");
    }

    #[tokio::test]
    async fn from_env_unset() {
        let name = child_test_name(module_path!(), "from_env_unset");
        if !is_child(&name) {
            run_child(
                &name,
                &[(ENV_FILE, "")],
                &[
                    crate::ENV_OIDC_ISSUER,
                    crate::ENV_OIDC_AUDIENCE,
                    crate::ENV_OIDC_JWKS_URL,
                ],
            );
            return;
        }
        let s = Store::from_env().await.expect("from_env");
        assert!(s.is_none(), "expected no store when env unset, got {s:?}");
    }

    #[tokio::test]
    async fn from_env_set() {
        let name = child_test_name(module_path!(), "from_env_set");
        if !is_child(&name) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = write_file(
                &dir,
                r#"{"principals": [{"name": "a", "token": "t", "admin": true}]}"#,
            );
            let path = path.to_str().expect("utf-8 path");
            run_child(&name, &[(ENV_FILE, path)], &[crate::ENV_OIDC_ISSUER]);
            return;
        }
        let s = Store::from_env()
            .await
            .expect("from_env")
            .expect("store when env set");
        assert!(s.identify("t").await.is_some());
    }

    #[tokio::test]
    async fn from_env_set_bad_file() {
        let name = child_test_name(module_path!(), "from_env_set_bad_file");
        if !is_child(&name) {
            let dir = tempfile::tempdir().expect("tempdir");
            let missing = dir.path().join("missing.json");
            let missing = missing.to_str().expect("utf-8 path");
            run_child(&name, &[(ENV_FILE, missing)], &[crate::ENV_OIDC_ISSUER]);
            return;
        }
        assert!(Store::from_env().await.is_err());
    }

    #[tokio::test]
    async fn identify() {
        let s = load(r#"{"principals": [{"name": "dev", "token": "secret"}]}"#).expect("load");
        let got = s.identify("secret").await.expect("known token");
        assert_eq!(got.name, "dev");
        assert!(s.identify("wrong").await.is_none());
        assert!(s.identify("").await.is_none());
    }

    #[test]
    fn tenant_id_defaults_to_name_and_can_be_shared() {
        let legacy = Principal {
            name: "alice".into(),
            ..p()
        };
        assert_eq!(legacy.tenant_id(), "alice");
        let shared = Principal {
            name: "codex".into(),
            tenant: "team-alpha".into(),
            ..p()
        };
        assert_eq!(shared.tenant_id(), "team-alpha");
    }

    #[tokio::test]
    async fn identify_scans_every_principal() {
        let s = load(
            r#"{"principals": [{"name": "dev", "token": "secret-dev"}, {"name": "ops", "token": "secret-ops"}]}"#,
        )
        .expect("load");
        let got = s.identify("secret-ops").await.expect("hit");
        assert_eq!(got.name, "ops");
    }

    #[tokio::test]
    async fn identify_empty_store() {
        let s = Store::from_principals(Vec::new()).expect("empty store");
        assert!(s.identify("anything").await.is_none());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn can_launch() {
        let cases: &[(&str, Principal, &str, bool)] = &[
            (
                "admin bypass",
                Principal { admin: true, ..p() },
                "anything",
                true,
            ),
            (
                "star all",
                Principal {
                    allowed_profiles: profiles(&["*"]),
                    ..p()
                },
                "build",
                true,
            ),
            (
                "team glob hit",
                Principal {
                    allowed_profiles: profiles(&["team-*"]),
                    ..p()
                },
                "team-alpha",
                true,
            ),
            (
                "team glob miss",
                Principal {
                    allowed_profiles: profiles(&["team-*"]),
                    ..p()
                },
                "prod",
                false,
            ),
            (
                "exact hit",
                Principal {
                    allowed_profiles: profiles(&["build"]),
                    ..p()
                },
                "build",
                true,
            ),
            (
                "exact miss",
                Principal {
                    allowed_profiles: profiles(&["build"]),
                    ..p()
                },
                "test",
                false,
            ),
            ("empty list non-admin", p(), "build", false),
            (
                "multi pattern hit",
                Principal {
                    allowed_profiles: profiles(&["a", "b-*"]),
                    ..p()
                },
                "b-1",
                true,
            ),
            (
                "glob does not cross slash",
                Principal {
                    allowed_profiles: profiles(&["team-*"]),
                    ..p()
                },
                "team-a/b",
                false,
            ),
            (
                "bad pattern never matches",
                Principal {
                    allowed_profiles: profiles(&["[", "x"]),
                    ..p()
                },
                "[",
                false,
            ),
        ];
        for (name, principal, profile, want) in cases {
            assert_eq!(principal.can_launch(profile), *want, "{name}");
        }
    }

    #[test]
    fn may_approve() {
        assert!(Principal { admin: true, ..p() }.may_approve());
        assert!(
            Principal {
                can_approve: true,
                ..p()
            }
            .may_approve()
        );
        assert!(!p().may_approve());
    }

    #[test]
    fn can_approve_profile() {
        assert!(
            Principal {
                can_approve: true,
                ..p()
            }
            .can_approve_profile("any")
        );
        let scoped = Principal {
            can_approve: true,
            approval_profiles: profiles(&["team-*"]),
            ..p()
        };
        assert!(scoped.can_approve_profile("team-dev"));
        assert!(!scoped.can_approve_profile("prod"));
        assert!(!p().can_approve_profile("team-dev"));
        let admin = Principal {
            admin: true,
            approval_profiles: profiles(&["team-*"]),
            ..p()
        };
        assert!(admin.can_approve_profile("prod"));
    }

    #[test]
    fn validate_for_network() {
        let s = load(r#"{"principals":[{"name":"short","token":"tiny"}]}"#).expect("load");
        assert!(s.validate_for_network().is_err());
        let long = Store::from_principals(vec![Principal {
            name: "long".into(),
            token: "x".repeat(32),
            ..p()
        }])
        .expect("store");
        assert!(long.validate_for_network().is_ok());
    }

    #[test]
    fn may_launch() {
        let cases: &[(&str, Principal, bool)] = &[
            ("admin", Principal { admin: true, ..p() }, true),
            (
                "star",
                Principal {
                    allowed_profiles: profiles(&["*"]),
                    ..p()
                },
                true,
            ),
            (
                "named",
                Principal {
                    allowed_profiles: profiles(&["dev"]),
                    ..p()
                },
                true,
            ),
            ("empty list", p(), false),
            (
                "blank patterns only",
                Principal {
                    allowed_profiles: profiles(&["", "  "]),
                    ..p()
                },
                false,
            ),
        ];
        for (name, principal, want) in cases {
            assert_eq!(principal.may_launch(), *want, "{name}");
        }
    }

    #[test]
    fn debug_redacts_token() {
        let principal = Principal {
            name: "a".into(),
            token: "super-secret-token".into(),
            ..p()
        };
        assert!(!format!("{principal:?}").contains("super-secret-token"));
    }

    #[test]
    fn serialize_omits_empty_optional_fields() {
        let json = serde_json::to_value(Principal {
            name: "a".into(),
            token: "t".into(),
            ..p()
        })
        .expect("serialize");
        assert!(json.get("tenant").is_none());
        assert!(json.get("approval_profiles").is_none());
        assert_eq!(json["name"], "a");
    }
}
