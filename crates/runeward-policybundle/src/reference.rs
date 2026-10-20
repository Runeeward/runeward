//! OCI reference parsing with the same rules as oras-go's
//! `registry.ParseReference`: `<registry>/<repository>[:<tag>|@<digest>]`.
//!
//! Unlike Docker-style parsers there is no `docker.io` / `library/`
//! normalisation and no implicit `latest` tag; an empty reference stays empty.

use std::sync::LazyLock;

use regex::Regex;

use crate::digest;

static REGISTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._~%!$&'()*+,;=-]+)(?::[0-9]*)?$")
        .expect("static registry regex")
});
static REPOSITORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*)*$",
    )
    .expect("static repository regex")
});
static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\w[\w.-]{0,127}$").expect("static tag regex"));

/// A parsed `<registry>/<repository>[:<tag>|@<digest>]` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reference {
    pub registry: String,
    pub repository: String,
    /// Tag or digest; empty when the reference names only a repository.
    pub reference: String,
}

impl Reference {
    /// Parses `s`, returning the reason it is invalid on failure.
    pub fn parse(s: &str) -> Result<Self, String> {
        let Some((registry, path)) = s.split_once('/') else {
            return Err("missing registry or repository".into());
        };
        let (repository, reference, is_tag) = if let Some((repo, digest)) = path.split_once('@') {
            // A tag alongside a digest is dropped without validation.
            let repo = repo.split_once(':').map_or(repo, |(r, _)| r);
            (repo, digest, false)
        } else if let Some((repo, tag)) = path.split_once(':') {
            (repo, tag, true)
        } else {
            (path, "", false)
        };

        if !REGISTRY.is_match(registry) {
            return Err(format!("invalid registry {registry:?}"));
        }
        if !REPOSITORY.is_match(repository) {
            return Err(format!("invalid repository {repository:?}"));
        }
        if !reference.is_empty() {
            if is_tag {
                if !TAG.is_match(reference) {
                    return Err(format!("invalid tag {reference:?}"));
                }
            } else if let Err(e) = digest::validate(reference) {
                return Err(format!("invalid digest {reference:?}: {e}"));
            }
        }
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            reference: reference.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_oras_forms() {
        let d = format!("sha256:{}", "a".repeat(64));
        let cases = [
            (
                "localhost:5000/runeward/policy:v1",
                "localhost:5000",
                "runeward/policy",
                "v1",
            ),
            ("ghcr.io/org/repo", "ghcr.io", "org/repo", ""),
            (
                &format!("r.io/repo@{d}") as &str,
                "r.io",
                "repo",
                &d as &str,
            ),
            (&format!("r.io/repo:ignored@{d}"), "r.io", "repo", &d),
            ("[::1]:5000/repo:latest", "[::1]:5000", "repo", "latest"),
        ];
        for (input, reg, repo, r) in cases {
            let got = Reference::parse(input).expect(input);
            assert_eq!(
                (
                    got.registry.as_str(),
                    got.repository.as_str(),
                    got.reference.as_str()
                ),
                (reg, repo, r),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_invalid_references() {
        for bad in [
            "repo",
            "r.io/Upper",
            "r.io/repo:-bad",
            "r.io/repo@sha256:abc",
            "r.io/repo@md5:00",
            "user@r.io/repo",
            "r.io:port/repo",
            "/repo",
        ] {
            assert!(Reference::parse(bad).is_err(), "{bad} should be rejected");
        }
    }
}
