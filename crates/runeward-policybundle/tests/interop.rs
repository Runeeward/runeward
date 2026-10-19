//! Live-registry interop with the Go implementation.
//!
//! Skipped unless `RUNEWARD_TEST_REGISTRY` names a plain-HTTP registry
//! (e.g. `127.0.0.1:5000`). When `RUNEWARD_TEST_GO_CLI` points at a built Go
//! `runeward` binary, bundles are also exchanged with it in both directions.

use std::path::Path;
use std::process::Command;

use runeward_policybundle::{
    Bundle, Engine, PullOptions, PushOptions, decode_private_key, decode_public_key, pull, push,
};

const POLICY: &str = "package runeward\n\ndecision := \"allow\"\n";
const QUERY: &str = "data.runeward.decision";

fn registry() -> Option<String> {
    std::env::var("RUNEWARD_TEST_REGISTRY")
        .ok()
        .filter(|s| !s.is_empty())
}

fn go(cli: &Path, args: &[&str]) -> String {
    let out = Command::new(cli).args(args).output().expect("run Go CLI");
    assert!(
        out.status.success(),
        "Go CLI {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test]
async fn live_registry_round_trip_and_go_interop() {
    let Some(reg) = registry() else {
        eprintln!("RUNEWARD_TEST_REGISTRY unset; skipping live registry test");
        return;
    };
    let plain = PushOptions { plain_http: true };
    let pull_opts = PullOptions { plain_http: true };
    let key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let public = key.verifying_key();

    // Rust push -> Rust pull.
    let src = Bundle::new(Engine::Cel, "[[cel]]\nexpr = 'true'\nverdict = \"allow\"\n");
    let digest = push(
        &format!("oci://{reg}/runeward/rust-only:v1"),
        &src,
        &key,
        plain,
    )
    .await
    .expect("rust push");
    let got = pull(
        &format!("{reg}/runeward/rust-only:v1"),
        Some(&public),
        pull_opts,
    )
    .await
    .expect("rust pull");
    assert_eq!((got.engine, &got.policy), (Engine::Cel, &src.policy));
    let by_digest = pull(
        &format!("{reg}/runeward/rust-only@{digest}"),
        Some(&public),
        pull_opts,
    )
    .await
    .expect("pull by digest");
    assert_eq!(by_digest.policy, src.policy);

    let Some(cli) = std::env::var_os("RUNEWARD_TEST_GO_CLI") else {
        eprintln!("RUNEWARD_TEST_GO_CLI unset; skipping Go interop");
        return;
    };
    let cli = Path::new(&cli);
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = dir.path().join("keys");
    go(
        cli,
        &["archive", "keygen", "--out", keys.to_str().expect("utf8")],
    );
    let key_file = keys.join("bundle.key");
    let pub_file = keys.join("bundle.pub");
    let go_key =
        decode_private_key(&std::fs::read_to_string(&key_file).expect("key")).expect("go key");
    let go_pub =
        decode_public_key(&std::fs::read_to_string(&pub_file).expect("pub")).expect("go pub");
    let policy_file = dir.path().join("policy.rego");
    std::fs::write(&policy_file, POLICY).expect("write policy");

    // Go push -> Rust pull + verify.
    let go_ref = format!("oci://{reg}/runeward/from-go:v1");
    go(
        cli,
        &[
            "archive",
            "push",
            &go_ref,
            "--policy",
            policy_file.to_str().expect("utf8"),
            "--engine",
            "rego",
            "--query",
            QUERY,
            "--key",
            key_file.to_str().expect("utf8"),
            "--plain-http",
        ],
    );
    let got = pull(&go_ref, Some(&go_pub), pull_opts)
        .await
        .expect("rust pull of Go bundle");
    assert_eq!(got.engine, Engine::Rego);
    assert_eq!(got.query.as_deref(), Some(QUERY));
    assert_eq!(got.policy, POLICY.as_bytes());
    assert!(
        pull(&go_ref, Some(&public), pull_opts).await.is_err(),
        "wrong key must fail"
    );

    // Rust push -> Go pull --verify-key.
    let rust_ref = format!("oci://{reg}/runeward/from-rust:v1");
    let bundle = Bundle::new(Engine::Rego, POLICY).with_query(QUERY);
    push(&rust_ref, &bundle, &go_key, plain)
        .await
        .expect("rust push");
    let out_file = dir.path().join("pulled.rego");
    let stdout = go(
        cli,
        &[
            "archive",
            "pull",
            &rust_ref,
            "--verify-key",
            pub_file.to_str().expect("utf8"),
            "--plain-http",
            "--out",
            out_file.to_str().expect("utf8"),
        ],
    );
    assert!(stdout.contains("verified: yes"), "{stdout}");
    assert!(stdout.contains(&format!("query:    {QUERY}")), "{stdout}");
    assert_eq!(std::fs::read_to_string(&out_file).expect("pulled"), POLICY);
}
