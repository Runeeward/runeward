//! Signing tools: `archive keygen|push|pull` for OCI policy bundles and
//! `charter sign|verify` for detached Charter signatures.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use ed25519_dalek::{SigningKey, VerifyingKey};
use runeward_charter::Signature;
use runeward_policybundle::{Bundle, Engine, PullOptions, PushOptions};

use crate::common::{go_io_error, go_join, go_quote, read_file};

/// Bounds a registry push or pull.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(60);

/// Reads a base64 ed25519 private key file (from `archive keygen`).
pub fn load_private_key(path: &str) -> Result<SigningKey> {
    let b = read_file(path).map_err(|e| anyhow!("read key: {e}"))?;
    Ok(runeward_policybundle::decode_private_key(
        String::from_utf8_lossy(&b).trim(),
    )?)
}

/// Accepts an inline base64 public key or a path to a file containing one.
pub fn load_public_key(key_or_path: &str) -> Result<VerifyingKey> {
    let mut val = key_or_path.trim().to_owned();
    if let Ok(b) = std::fs::read(&val) {
        val = String::from_utf8_lossy(&b).trim().to_owned();
    }
    Ok(runeward_policybundle::decode_public_key(&val)?)
}

#[cfg(unix)]
fn write_mode(path: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_mode(path: &str, data: &[u8], _mode: u32) -> std::io::Result<()> {
    std::fs::write(path, data)
}

/// Writes a file the way Go's `os.WriteFile` does, with Go-style errors.
pub fn write_file(path: &str, data: &[u8], mode: u32) -> Result<()> {
    write_mode(path, data, mode).map_err(|e| anyhow!(go_io_error("open", path, &e)))
}

/// Creates a directory tree (Go's `os.MkdirAll` with `mode`).
pub fn mkdir_all(dir: &str, mode: u32) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    b.create(dir)
}

/// `runeward archive keygen [--out dir]`.
pub fn keygen(out: &str) -> Result<()> {
    let mut secret = [0u8; 32];
    rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut secret)
        .expect("system random source");
    let key = SigningKey::from_bytes(&secret);
    let public = key.verifying_key();
    let pub_b64 = runeward_policybundle::encode_key(public.as_bytes());
    let priv_b64 = runeward_policybundle::encode_key(&key.to_keypair_bytes());
    let key_id = runeward_policybundle::key_id(&public);
    if out.is_empty() {
        println!("key-id:      {key_id}");
        println!("public-key:  {pub_b64}");
        println!("private-key: {priv_b64}");
        return Ok(());
    }
    mkdir_all(out, 0o700).map_err(|e| anyhow!(go_io_error("mkdir", out, &e)))?;
    let key_path = go_join(&[out, "bundle.key"]);
    let pub_path = go_join(&[out, "bundle.pub"]);
    // Both halves are base64 so `archive push --key` and a Charter's
    // verify_key can consume them directly.
    write_file(&key_path, format!("{priv_b64}\n").as_bytes(), 0o600)?;
    write_file(&pub_path, format!("{pub_b64}\n").as_bytes(), 0o644)?;
    println!(
        "key-id:     {key_id}\nprivate:    {key_path}\npublic:     {pub_path}\npublic-key: {pub_b64}"
    );
    Ok(())
}

/// `runeward archive push <ref>`.
pub async fn push(
    reference: &str,
    policy_file: &str,
    engine: &str,
    query: &str,
    key_file: &str,
    plain_http: bool,
) -> Result<()> {
    let engine = match engine {
        "rego" => Engine::Rego,
        "cel" => Engine::Cel,
        other => bail!(
            "--engine must be \"rego\" or \"cel\", got {}",
            go_quote(other)
        ),
    };
    if policy_file.is_empty() {
        bail!("--policy is required");
    }
    if key_file.is_empty() {
        bail!("--key is required");
    }
    let policy = read_file(policy_file).map_err(|e| anyhow!("read policy: {e}"))?;
    let key = load_private_key(key_file)?;
    let mut bundle = Bundle::new(engine, policy);
    if !query.is_empty() {
        bundle = bundle.with_query(query);
    }
    let digest = tokio::time::timeout(
        REGISTRY_TIMEOUT,
        runeward_policybundle::push(reference, &bundle, &key, PushOptions { plain_http }),
    )
    .await
    .map_err(|_| anyhow!("context deadline exceeded"))??;
    println!(
        "pushed {}\ndigest: {digest}",
        runeward_policybundle::strip_scheme(reference)
    );
    Ok(())
}

/// `runeward archive pull <ref>`.
pub async fn pull(reference: &str, verify_key: &str, plain_http: bool, out: &str) -> Result<()> {
    let verify = if verify_key.is_empty() {
        None
    } else {
        Some(load_public_key(verify_key)?)
    };
    let b = tokio::time::timeout(
        REGISTRY_TIMEOUT,
        runeward_policybundle::pull(reference, verify.as_ref(), PullOptions { plain_http }),
    )
    .await
    .map_err(|_| anyhow!("context deadline exceeded"))??;
    let verified = if verify.is_some() {
        "yes"
    } else {
        "no (no verify key supplied)"
    };
    println!("engine:   {}", b.engine.as_str());
    if let Some(q) = b.query.as_deref().filter(|q| !q.is_empty()) {
        println!("query:    {q}");
    }
    println!("verified: {verified}");
    if !out.is_empty() {
        write_file(out, &b.policy, 0o644)?;
        println!("policy written to {out} ({} bytes)", b.policy.len());
        return Ok(());
    }
    println!("policy:\n{}", String::from_utf8_lossy(&b.policy));
    Ok(())
}

/// `runeward charter sign <file>`.
pub fn charter_sign(file: &str, key_file: &str, out: &str) -> Result<()> {
    if key_file.is_empty() {
        bail!("--key is required");
    }
    let content = read_file(file).map_err(|e| anyhow!("read charter: {e}"))?;
    let key = load_private_key(key_file)?;
    let sig = Signature::new(&content, &key);
    let sig_bytes = sig.marshal();
    if out == "-" {
        use std::io::Write;
        std::io::stdout().write_all(&sig_bytes)?;
        return Ok(());
    }
    let sig_path = if out.is_empty() {
        format!("{file}.sig")
    } else {
        out.to_owned()
    };
    write_file(&sig_path, &sig_bytes, 0o644)?;
    println!(
        "signed {file}\nkey-id:    {}\nsignature: {sig_path}",
        sig.key_id
    );
    Ok(())
}

/// `runeward charter verify <file>`.
pub fn charter_verify(file: &str, verify_key: &str, sig_file: &str) -> Result<()> {
    if verify_key.is_empty() {
        bail!("--verify-key is required");
    }
    let content = read_file(file).map_err(|e| anyhow!("read charter: {e}"))?;
    let sig_path = if sig_file.is_empty() {
        format!("{file}.sig")
    } else {
        sig_file.to_owned()
    };
    let sig_bytes = read_file(&sig_path).map_err(|e| anyhow!("read signature: {e}"))?;
    let sig = Signature::parse(&sig_bytes)?;
    let public = load_public_key(verify_key)?;
    let key_id = sig.verify(&content, &public)?;
    println!("verified: {key_id}");
    Ok(())
}
