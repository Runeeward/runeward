//! Content digests (`<algorithm>:<hex>`) with the algorithms go-digest
//! registers by default: sha256, sha384 and sha512.

use sha2::{Digest as _, Sha256, Sha384, Sha512};

/// Returns the canonical sha256 digest of `data`.
pub(crate) fn sha256(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

/// Checks that `digest` is well formed and uses a supported algorithm.
pub(crate) fn validate(digest: &str) -> Result<(), String> {
    let (alg, encoded) = digest
        .split_once(':')
        .ok_or_else(|| "invalid checksum digest format".to_owned())?;
    let want = match alg {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        other => return Err(format!("unsupported digest algorithm {other:?}")),
    };
    let lower_hex = encoded
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if encoded.len() != want || !lower_hex {
        return Err("invalid checksum digest format".into());
    }
    Ok(())
}

/// Computes the digest of `data` with the algorithm named by `digest`.
pub(crate) fn compute_like(digest: &str, data: &[u8]) -> Result<String, String> {
    validate(digest)?;
    let (alg, _) = digest.split_once(':').unwrap_or_default();
    let encoded = match alg {
        "sha256" => hex::encode(Sha256::digest(data)),
        "sha384" => hex::encode(Sha384::digest(data)),
        _ => hex::encode(Sha512::digest(data)),
    };
    Ok(format!("{alg}:{encoded}"))
}
