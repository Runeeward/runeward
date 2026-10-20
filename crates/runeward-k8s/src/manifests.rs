//! Embedded CustomResourceDefinitions and the controller install bundle used
//! by `runeward up`.
//!
//! The YAML under `internal/manifests/{crds,install}` is canonical and is
//! embedded here byte for byte (it is referenced in place, not copied). The
//! copies under `deploy/crds` and `deploy/helm/runeward/crds` are kept in sync
//! by a drift test.

/// One embedded manifest document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Manifest {
    /// File name, e.g. `runeward.dev_citadels.yaml`.
    pub name: &'static str,
    /// The YAML document, byte-identical to the shipped file.
    pub content: &'static str,
}

macro_rules! manifest {
    ($dir:literal, $name:literal) => {
        Manifest {
            name: $name,
            content: include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/manifests/",
                $dir,
                "/",
                $name
            )),
        }
    };
}

/// CRD documents, sorted by file name.
static CRDS: &[Manifest] = &[
    manifest!("crds", "runeward.dev_citadels.yaml"),
    manifest!("crds", "runeward.dev_clustercitadels.yaml"),
    manifest!("crds", "runeward.dev_clustercohorts.yaml"),
    manifest!("crds", "runeward.dev_clusterpolicies.yaml"),
    manifest!("crds", "runeward.dev_cohorts.yaml"),
];

/// Install bundle documents, sorted by file name (numeric prefixes order them).
static INSTALL: &[Manifest] = &[
    manifest!("install", "00-namespace.yaml"),
    manifest!("install", "20-rbac.yaml"),
    manifest!("install", "21-clusterrbac.yaml"),
    manifest!("install", "30-deployment.yaml"),
];

/// Returns the CustomResourceDefinition documents, sorted by file name.
pub fn crds() -> &'static [Manifest] {
    CRDS
}

/// Returns the controller install bundle documents, sorted by file name
/// (numeric prefixes order them).
pub fn install() -> &'static [Manifest] {
    INSTALL
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn yaml_files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read manifest dir")
            .map(|e| e.expect("dir entry"))
            .filter(|e| e.file_type().expect("file type").is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".yaml"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn embedded_manifests_load() {
        assert_eq!(crds().len(), 5, "expected 5 CRDs");
        assert!(install().len() >= 3, "expected >=3 install docs");
    }

    #[test]
    fn embedded_lists_cover_every_file_in_order() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("manifests");
        for (dir, embedded) in [("crds", crds()), ("install", install())] {
            let on_disk = yaml_files(&base.join(dir));
            let names: Vec<&str> = embedded.iter().map(|m| m.name).collect();
            assert_eq!(names, on_disk, "embedded {dir} list is stale");
            for m in embedded {
                let bytes = std::fs::read(base.join(dir).join(m.name)).expect("read manifest");
                assert_eq!(m.content.as_bytes(), bytes.as_slice(), "{dir}/{}", m.name);
            }
        }
    }

    /// Guards against drift between the embedded CRDs and the deploy/ copies.
    #[test]
    fn crd_copies_in_sync() {
        for m in crds() {
            for copy_dir in ["deploy/crds", "deploy/helm/runeward/crds"] {
                let p = repo_root().join(copy_dir).join(m.name);
                let got = std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
                assert!(
                    got == m.content.as_bytes(),
                    "{} differs from embedded canonical crds/{}; run: cp crates/runeward-k8s/manifests/crds/{} {}/",
                    p.display(),
                    m.name,
                    m.name,
                    copy_dir
                );
            }
        }
    }
}
