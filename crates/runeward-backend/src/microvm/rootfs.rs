//! OCI image -> read-only ext4 image disk, cached by manifest digest.
//!
//! The image is pulled straight from its registry (anonymously, like the
//! policy bundle client; no container engine), for `linux/<host arch>`.
//! Layers are verified against their digests, applied in order with OCI
//! whiteouts into a staging directory (all writes confined to it with
//! [`cap_std`], so a hostile layer cannot write outside), and turned into
//! an ext4 image with the real owners and modes ([`super::ext4`]). The
//! image disk is attached read-only to every VM that uses it; the guest
//! writes into a memory overlay, so the cached disk never changes.
//!
//! Layout under `<RUNEWARD_MICROVM_DIR>/images`:
//!
//! - `sha256-<hex>.ext4`, `sha256-<hex>.json`: the disk and the image
//!   config (`Env`, `User`, `WorkingDir`) for a manifest digest;
//! - `refs.json`: the digest each reference last resolved to, so a cached
//!   image still starts when the registry is unreachable;
//! - `tmp/`: downloads and staging, removed after each build.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest::{ImageIndexEntry, OciDescriptor};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::ext4::{Meta, S_IFDIR, S_IFLNK, S_IFREG, Tools, image_size};
use crate::error::{BackendError, Result};

/// The largest image config document accepted.
const MAX_CONFIG_BYTES: usize = 4 << 20;

/// What the guest needs from the image config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ImageConfig {
    /// `KEY=value` environment.
    pub(crate) env: Vec<String>,
    /// The image's `USER`.
    pub(crate) user: String,
    /// The image's `WORKDIR`.
    pub(crate) working_dir: String,
}

impl ImageConfig {
    /// Parses an OCI image config document (`config.Env`, `config.User`,
    /// `config.WorkingDir`).
    pub(crate) fn from_oci(doc: &[u8]) -> Result<Self> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Inner {
            #[serde(rename = "Env")]
            env: Option<Vec<String>>,
            #[serde(rename = "User")]
            user: Option<String>,
            #[serde(rename = "WorkingDir")]
            working_dir: Option<String>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Outer {
            config: Option<Inner>,
        }
        let o: Outer = serde_json::from_slice(doc)
            .map_err(|e| BackendError::msg(format!("parse image config: {e}")))?;
        let c = o.config.unwrap_or_default();
        Ok(Self {
            env: c.env.unwrap_or_default(),
            user: c.user.unwrap_or_default(),
            working_dir: c.working_dir.unwrap_or_default(),
        })
    }

    /// The environment as a map (later entries win).
    pub(crate) fn env_map(&self) -> BTreeMap<String, String> {
        self.env
            .iter()
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }
}

/// A cached image disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Image {
    /// The reference it was pulled as.
    pub(crate) reference: String,
    /// The platform manifest digest.
    pub(crate) digest: String,
    /// The ext4 image disk.
    pub(crate) rootfs: PathBuf,
    /// The image config.
    pub(crate) config: ImageConfig,
}

/// The OCI architecture name of this host.
pub(crate) fn oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Builds and caches image disks.
#[derive(Debug)]
pub(crate) struct ImageStore {
    dir: PathBuf,
    tools: Tools,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

fn digest_hex(digest: &str) -> Result<&str> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| BackendError::msg(format!("unsupported digest {digest:?}")))?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BackendError::msg(format!("malformed digest {digest:?}")));
    }
    Ok(hex)
}

impl ImageStore {
    /// A store under `dir`.
    pub(crate) fn new(dir: PathBuf, tools: Tools) -> Self {
        Self {
            dir,
            tools,
            locks: Mutex::new(HashMap::new()),
        }
    }

    fn client() -> Client {
        // reqwest is built without a bundled crypto provider; use ring like
        // the rest of the workspace. Failure means one is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let arch = oci_arch();
        Client::new(ClientConfig {
            protocol: ClientProtocol::Https,
            platform_resolver: Some(Box::new(move |entries: &[ImageIndexEntry]| {
                entries
                    .iter()
                    .find(|e| {
                        e.platform.as_ref().is_some_and(|p| {
                            p.os.to_string() == "linux" && p.architecture.to_string() == arch
                        })
                    })
                    .map(|e| e.digest.clone())
            })),
            ..ClientConfig::default()
        })
    }

    fn paths(&self, digest: &str) -> Result<(PathBuf, PathBuf)> {
        let hex = digest_hex(digest)?;
        Ok((
            self.dir.join(format!("sha256-{hex}.ext4")),
            self.dir.join(format!("sha256-{hex}.json")),
        ))
    }

    fn refs_path(&self) -> PathBuf {
        self.dir.join("refs.json")
    }

    fn cached_ref(&self, reference: &str) -> Option<String> {
        let data = fs::read(self.refs_path()).ok()?;
        let refs: BTreeMap<String, String> = serde_json::from_slice(&data).ok()?;
        refs.get(reference).cloned()
    }

    fn remember_ref(&self, reference: &str, digest: &str) {
        let mut refs: BTreeMap<String, String> = fs::read(self.refs_path())
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        refs.insert(reference.to_owned(), digest.to_owned());
        if let Ok(data) = serde_json::to_vec_pretty(&refs) {
            let tmp = self.refs_path().with_extension("json.tmp");
            if fs::write(&tmp, data).is_ok() {
                let _ = fs::rename(tmp, self.refs_path());
            }
        }
    }

    /// The cached image for a digest, if built.
    fn load(&self, reference: &str, digest: &str) -> Option<Image> {
        let (rootfs, cfg) = self.paths(digest).ok()?;
        if !rootfs.is_file() {
            return None;
        }
        let config: ImageConfig = serde_json::from_slice(&fs::read(cfg).ok()?).ok()?;
        Some(Image {
            reference: reference.to_owned(),
            digest: digest.to_owned(),
            rootfs,
            config,
        })
    }

    /// Returns the image disk for `reference`, pulling and building it on
    /// first use.
    pub(crate) async fn ensure(&self, reference: &str) -> Result<Image> {
        let lock = {
            let mut locks = self.locks.lock().await;
            Arc::clone(locks.entry(reference.to_owned()).or_default())
        };
        let _held = lock.lock().await;
        fs::create_dir_all(&self.dir)
            .map_err(|e| BackendError::io(format!("create {}", self.dir.display()), e))?;
        let r: Reference = reference
            .parse()
            .map_err(|e| BackendError::msg(format!("image reference {reference:?}: {e}")))?;
        let client = Self::client();
        let (manifest, digest) = match client
            .pull_image_manifest(&r, &RegistryAuth::Anonymous)
            .await
        {
            Ok(m) => m,
            Err(e) => {
                // Offline (or registry trouble): a disk built earlier for
                // this reference still boots.
                if let Some(d) = self.cached_ref(reference)
                    && let Some(img) = self.load(reference, &d)
                {
                    tracing::warn!(target: "runeward_backend", "resolve {reference}: {e}; using the cached image {d}");
                    return Ok(img);
                }
                return Err(BackendError::msg(format!(
                    "pull image {reference} for linux/{}: {e}",
                    oci_arch()
                )));
            }
        };
        if let Some(img) = self.load(reference, &digest) {
            self.remember_ref(reference, &digest);
            return Ok(img);
        }
        let tmp = self.dir.join("tmp").join(digest_hex(&digest)?);
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp)
            .map_err(|e| BackendError::io(format!("create {}", tmp.display()), e))?;
        let built = self
            .build(
                &client,
                &r,
                &digest,
                &manifest.config,
                &manifest.layers,
                &tmp,
            )
            .await;
        let _ = fs::remove_dir_all(&tmp);
        let img = built?;
        self.remember_ref(reference, &digest);
        Ok(Image {
            reference: reference.to_owned(),
            ..img
        })
    }

    async fn build(
        &self,
        client: &Client,
        r: &Reference,
        digest: &str,
        config: &OciDescriptor,
        layers: &[OciDescriptor],
        tmp: &Path,
    ) -> Result<Image> {
        let mut cfg_doc = Vec::new();
        client
            .pull_blob(r, config, &mut cfg_doc)
            .await
            .map_err(|e| BackendError::msg(format!("pull image config: {e}")))?;
        if cfg_doc.len() > MAX_CONFIG_BYTES {
            return Err(BackendError::msg("image config is too large"));
        }
        let image_config = ImageConfig::from_oci(&cfg_doc)?;
        let mut files = Vec::with_capacity(layers.len());
        for (i, l) in layers.iter().enumerate() {
            let path = tmp.join(format!("layer-{i}"));
            let mut f = tokio::fs::File::create(&path)
                .await
                .map_err(|e| BackendError::io("create layer file", e))?;
            client
                .pull_blob(r, l, &mut f)
                .await
                .map_err(|e| BackendError::msg(format!("pull layer {}: {e}", l.digest)))?;
            files.push(path);
        }
        let staging = tmp.join("rootfs");
        let tree = {
            let (staging, files) = (staging.clone(), files.clone());
            tokio::task::spawn_blocking(move || flatten(&files, &staging))
                .await
                .map_err(|e| BackendError::msg(format!("unpack layers: {e}")))??
        };
        for f in &files {
            let _ = fs::remove_file(f);
        }
        let (rootfs, cfg_path) = self.paths(digest)?;
        let part = rootfs.with_extension("ext4.part");
        let size = image_size(tree.bytes, tree.meta.len() as u64);
        if let Err(e) = self
            .tools
            .make_from_dir(&staging, &tree.meta, &part, size)
            .await
        {
            let _ = fs::remove_file(&part);
            return Err(e);
        }
        fs::write(
            &cfg_path,
            serde_json::to_vec_pretty(&image_config).unwrap_or_default(),
        )
        .map_err(|e| BackendError::io("write image config", e))?;
        fs::rename(&part, &rootfs).map_err(|e| BackendError::io("store image disk", e))?;
        tracing::info!(target: "runeward_backend", "built image disk {} for {digest} ({} entries, {} MiB)", rootfs.display(), tree.meta.len(), size >> 20);
        Ok(Image {
            reference: String::new(),
            digest: digest.to_owned(),
            rootfs,
            config: image_config,
        })
    }
}

/// The unpacked tree: every entry's real owner and mode, and the bytes of
/// file data.
#[derive(Debug, Default)]
pub(crate) struct Tree {
    pub(crate) meta: BTreeMap<String, Meta>,
    pub(crate) bytes: u64,
}

impl Tree {
    /// Forgets `p` and everything under it.
    fn forget(&mut self, p: &str) {
        self.meta.remove(p);
        let prefix = format!("{p}/");
        let doomed: Vec<String> = self
            .meta
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect();
        for k in doomed {
            self.meta.remove(&k);
        }
    }
}

/// Normalises a layer entry name to a root-relative path; `None` for the
/// root itself, an error for names that climb out with `..`.
pub(crate) fn entry_path(name: &str) -> io::Result<Option<String>> {
    let mut parts = Vec::new();
    for c in name.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("layer entry {name:?} escapes the root"),
                ));
            }
            c => parts.push(c),
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

fn open_layer(path: &Path) -> io::Result<Box<dyn Read>> {
    let mut f = fs::File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    drop(f);
    let f = fs::File::open(path)?;
    if n >= 2 && magic[..2] == [0x1f, 0x8b] {
        return Ok(Box::new(flate2::read::GzDecoder::new(io::BufReader::new(
            f,
        ))));
    }
    if n == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "zstd-compressed layers are not supported; use a gzip or uncompressed image",
        ));
    }
    Ok(Box::new(io::BufReader::new(f)))
}

fn parent_of(p: &str) -> Option<&str> {
    p.rsplit_once('/').map(|(d, _)| d)
}

/// Removes `p` (file, link or directory tree) from the staging root.
fn remove_any(root: &Dir, p: &str) -> io::Result<()> {
    match root.symlink_metadata(p) {
        Ok(md) if md.is_dir() => root.remove_dir_all(p),
        Ok(_) => root.remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Creates the parents of `p` that do not exist yet (root-owned 0755 unless
/// a layer said otherwise).
fn ensure_parents(root: &Dir, tree: &mut Tree, p: &str) -> io::Result<()> {
    let Some(parent) = parent_of(p) else {
        return Ok(());
    };
    let mut acc = String::new();
    for c in parent.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(c);
        match root.symlink_metadata(&acc) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                root.create_dir(&acc)?;
                tree.meta.entry(acc.clone()).or_insert(Meta {
                    uid: 0,
                    gid: 0,
                    mode: S_IFDIR | 0o755,
                });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Applies the layers in `files` (bottom first) into `staging`.
pub(crate) fn flatten(files: &[PathBuf], staging: &Path) -> Result<Tree> {
    fs::create_dir_all(staging)
        .map_err(|e| BackendError::io(format!("create {}", staging.display()), e))?;
    let root = Dir::open_ambient_dir(staging, ambient_authority())
        .map_err(|e| BackendError::io("open staging root", e))?;
    let mut tree = Tree::default();
    for (i, f) in files.iter().enumerate() {
        apply_layer(&root, f, &mut tree)
            .map_err(|e| BackendError::io(format!("unpack layer {i}"), e))?;
    }
    Ok(tree)
}

/// Applies one layer: its whiteouts first (they only hide lower layers),
/// then its entries.
pub(crate) fn apply_layer(root: &Dir, file: &Path, tree: &mut Tree) -> io::Result<()> {
    let mut whiteouts = Vec::new();
    let mut opaque = Vec::new();
    {
        let mut a = tar::Archive::new(open_layer(file)?);
        for e in a.entries()? {
            let e = e?;
            let name = String::from_utf8_lossy(&e.path_bytes()).into_owned();
            let Some(p) = entry_path(&name)? else {
                continue;
            };
            let (dir, base) = match p.rsplit_once('/') {
                Some((d, b)) => (Some(d.to_owned()), b.to_owned()),
                None => (None, p.clone()),
            };
            if base == ".wh..wh..opq" {
                opaque.push(dir.unwrap_or_default());
            } else if let Some(hidden) = base.strip_prefix(".wh.") {
                whiteouts.push(match dir {
                    Some(d) => format!("{d}/{hidden}"),
                    None => hidden.to_owned(),
                });
            }
        }
    }
    for p in &whiteouts {
        entry_path(p)?;
        remove_any(root, p)?;
        tree.forget(p);
    }
    for d in &opaque {
        let entries: Vec<String> = match if d.is_empty() {
            root.entries()
        } else {
            root.read_dir(d)
        } {
            Ok(it) => it
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        for name in entries {
            let p = if d.is_empty() {
                name
            } else {
                format!("{d}/{name}")
            };
            remove_any(root, &p)?;
            tree.forget(&p);
        }
    }
    let mut a = tar::Archive::new(open_layer(file)?);
    for e in a.entries()? {
        let mut e = e?;
        let name = String::from_utf8_lossy(&e.path_bytes()).into_owned();
        let Some(p) = entry_path(&name)? else {
            continue;
        };
        if p.rsplit('/').next().is_some_and(|b| b.starts_with(".wh.")) {
            continue;
        }
        let h = e.header();
        let (uid, gid) = (h.uid().unwrap_or(0), h.gid().unwrap_or(0));
        let perm = h.mode().unwrap_or(0o644) & 0o7777;
        let kind = h.entry_type();
        ensure_parents(root, tree, &p)?;
        match kind {
            tar::EntryType::Directory => {
                match root.symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => {}
                    Ok(_) => {
                        remove_any(root, &p)?;
                        root.create_dir(&p)?;
                    }
                    Err(_) => root.create_dir(&p)?,
                }
                tree.meta.insert(
                    p,
                    Meta {
                        uid,
                        gid,
                        mode: S_IFDIR | perm,
                    },
                );
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                remove_any(root, &p)?;
                let mut opts = cap_std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                let mut out = root.open_with(&p, &opts)?;
                let n = io::copy(&mut e, &mut out)?;
                drop(out);
                // Readable by the extracting user, so mkfs can copy it; the
                // real mode is applied in the image.
                set_mode(root, &p, (perm | 0o600) & 0o777)?;
                tree.bytes += n;
                tree.forget(&p);
                tree.meta.insert(
                    p,
                    Meta {
                        uid,
                        gid,
                        mode: S_IFREG | perm,
                    },
                );
            }
            tar::EntryType::Symlink => {
                let target = e
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                remove_any(root, &p)?;
                tree.forget(&p);
                // Only created, never followed: absolute targets are fine.
                symlink(root, &target, &p)?;
                tree.meta.insert(
                    p,
                    Meta {
                        uid,
                        gid,
                        mode: S_IFLNK | 0o777,
                    },
                );
            }
            tar::EntryType::Link => {
                let target = e
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                let Some(src) = entry_path(&target)? else {
                    continue;
                };
                remove_any(root, &p)?;
                tree.forget(&p);
                root.hard_link(&src, root, &p)?;
                if let Some(m) = tree.meta.get(&src).copied() {
                    tree.meta.insert(p, m);
                }
            }
            // Device nodes and FIFOs: the guest mounts its own /dev, and an
            // unprivileged build cannot create them.
            _ => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(root: &Dir, p: &str, mode: u32) -> io::Result<()> {
    use cap_std::fs::PermissionsExt;
    root.set_permissions(p, cap_std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_: &Dir, _: &str, _: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn symlink(root: &Dir, original: &str, link: &str) -> io::Result<()> {
    // `symlink_contents` accepts absolute targets (images are full of
    // them); the link itself is still created inside the root.
    root.symlink_contents(original, link)
}

#[cfg(not(unix))]
fn symlink(root: &Dir, original: &str, link: &str) -> io::Result<()> {
    root.symlink_file(original, link)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layer tar: (name, kind, contents or link target, uid, mode).
    fn layer(
        dir: &Path,
        n: usize,
        entries: &[(&str, char, &str, u64, u32)],
        gzip: bool,
    ) -> PathBuf {
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind, data, uid, mode) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_uid(*uid);
            h.set_gid(*uid);
            h.set_mode(*mode);
            h.set_mtime(0);
            match kind {
                'd' => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    b.append_data(&mut h, name, io::empty()).expect("dir");
                }
                'f' => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(data.len() as u64);
                    b.append_data(&mut h, name, data.as_bytes()).expect("file");
                }
                'l' => {
                    h.set_entry_type(tar::EntryType::Symlink);
                    h.set_size(0);
                    b.append_link(&mut h, name, data).expect("symlink");
                }
                'h' => {
                    h.set_entry_type(tar::EntryType::Link);
                    h.set_size(0);
                    b.append_link(&mut h, name, data).expect("hardlink");
                }
                _ => unreachable!(),
            }
        }
        let raw = b.into_inner().expect("tar");
        let path = dir.join(format!("layer-{n}"));
        if gzip {
            use std::io::Write;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&raw).expect("gzip");
            fs::write(&path, gz.finish().expect("gzip")).expect("write");
        } else {
            fs::write(&path, raw).expect("write");
        }
        path
    }

    #[test]
    fn layers_whiteouts_and_owners() {
        let d = tempfile::tempdir().expect("tempdir");
        let l0 = layer(
            d.path(),
            0,
            &[
                ("etc/", 'd', "", 0, 0o755),
                ("etc/shadow", 'f', "secret", 0, 0o000),
                ("etc/keep", 'f', "k", 0, 0o644),
                ("opt/app/", 'd', "", 0, 0o755),
                ("opt/app/old", 'f', "old", 0, 0o644),
                ("home/agent/", 'd', "", 1500, 0o700),
                ("bin/sh", 'f', "#!", 0, 0o755),
                ("bin/rbash", 'h', "bin/sh", 0, 0o755),
                ("usr/bin/vi", 'l', "/bin/sh", 0, 0o777),
            ],
            true,
        );
        let l1 = layer(
            d.path(),
            1,
            &[
                ("etc/.wh.keep", 'f', "", 0, 0o644),
                ("opt/app/.wh..wh..opq", 'f', "", 0, 0o644),
                ("opt/app/new", 'f', "new", 0, 0o4755),
                ("home/agent/notes", 'f', "hi", 1500, 0o600),
            ],
            false,
        );
        let staging = d.path().join("rootfs");
        let tree = flatten(&[l0, l1], &staging).expect("flatten");
        assert!(!staging.join("etc/keep").exists(), "whiteout removed it");
        assert!(!staging.join("opt/app/old").exists(), "opaque dir hid it");
        assert_eq!(
            fs::read_to_string(staging.join("opt/app/new")).expect("new"),
            "new"
        );
        // Unreadable in the image, readable for mkfs on the host.
        assert_eq!(
            fs::read_to_string(staging.join("etc/shadow")).expect("shadow"),
            "secret"
        );
        assert_eq!(tree.meta["etc/shadow"].mode, S_IFREG);
        assert_eq!(tree.meta["opt/app/new"].mode, S_IFREG | 0o4755);
        assert_eq!(tree.meta["home/agent"].uid, 1500);
        assert_eq!(tree.meta["home/agent/notes"].mode, S_IFREG | 0o600);
        assert_eq!(tree.meta["usr/bin/vi"].mode, S_IFLNK | 0o777);
        assert_eq!(tree.meta["usr"].mode, S_IFDIR | 0o755, "implied parent");
        assert!(!tree.meta.contains_key("etc/keep"));
        assert!(!tree.meta.contains_key("opt/app/old"));
        assert_eq!(
            fs::read_link(staging.join("usr/bin/vi")).expect("link"),
            PathBuf::from("/bin/sh")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let a = fs::metadata(staging.join("bin/sh")).expect("sh").ino();
            let b = fs::metadata(staging.join("bin/rbash"))
                .expect("rbash")
                .ino();
            assert_eq!(a, b, "hard link kept");
        }
    }

    #[test]
    fn hostile_layers_are_refused() {
        let d = tempfile::tempdir().expect("tempdir");
        // The tar crate refuses to build `..` names, so write one raw.
        let mut h = tar::Header::new_old();
        h.as_old_mut().name[..9].copy_from_slice(b"../escape");
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        b.append(&h, &b"x"[..]).expect("append");
        let l = d.path().join("layer-raw");
        fs::write(&l, b.into_inner().expect("tar")).expect("write");
        assert!(flatten(&[l], &d.path().join("r1")).is_err());
        assert!(!d.path().join("escape").exists());

        // A link pointing out of the root, then a write through it.
        let l = layer(
            d.path(),
            1,
            &[
                ("evil", 'l', "/", 0, 0o777),
                ("evil/tmp/pwned", 'f', "x", 0, 0o644),
            ],
            false,
        );
        assert!(flatten(&[l], &d.path().join("r2")).is_err());
    }

    #[test]
    fn entry_paths_and_config() {
        assert_eq!(
            entry_path("./usr//bin/").expect("ok").as_deref(),
            Some("usr/bin")
        );
        assert_eq!(entry_path("/abs").expect("ok").as_deref(), Some("abs"));
        assert_eq!(entry_path("./").expect("root"), None);
        assert!(entry_path("a/../../b").is_err());
        let c = ImageConfig::from_oci(
            br#"{"architecture":"amd64","config":{"Env":["PATH=/usr/bin","A=b=c"],"User":"agent","WorkingDir":"/w"}}"#,
        )
        .expect("config");
        assert_eq!(c.user, "agent");
        assert_eq!(c.working_dir, "/w");
        assert_eq!(c.env_map()["A"], "b=c");
        assert_eq!(
            ImageConfig::from_oci(b"{}").expect("empty"),
            ImageConfig::default()
        );
        assert!(digest_hex("sha256:abc").is_err());
        assert!(digest_hex(&format!("sha256:{}", "a".repeat(64))).is_ok());
    }
}
