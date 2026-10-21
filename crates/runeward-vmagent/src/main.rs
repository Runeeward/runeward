//! `runeward-vmagent`: see the library docs.
//!
//! - as PID 1 in a guest: boots the sandbox and serves the host;
//! - `__run ...` / `__file ...`: the helper modes the agent launches;
//! - `serve --unix PATH [--egress ADDR --egress-unix PATH]`: serves the
//!   protocol on a Unix socket for development and tests on a host;
//! - `--version`.

use std::process::ExitCode;

fn code(c: i32) -> ExitCode {
    ExitCode::from(u8::try_from(c).unwrap_or(1))
}

#[cfg(unix)]
fn serve(args: &[String]) -> ExitCode {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Arc;

    use runeward_vmagent::server::{Agent, HelperMode, HostPlatform, Reaper, forward_egress};

    let mut unix = None;
    let mut egress = None;
    let mut egress_unix = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--unix" => unix = it.next().cloned(),
            "--egress" => egress = it.next().cloned(),
            "--egress-unix" => egress_unix = it.next().cloned(),
            other => {
                eprintln!("runeward-vmagent serve: unknown flag {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = unix else {
        eprintln!("runeward-vmagent serve: --unix PATH is required");
        return ExitCode::from(2);
    };
    if let (Some(addr), Some(up)) = (egress, egress_unix) {
        match std::net::TcpListener::bind(&addr) {
            Ok(l) => {
                std::thread::spawn(move || forward_egress(l, move || UnixStream::connect(&up)));
            }
            Err(e) => {
                eprintln!("runeward-vmagent serve: egress {addr}: {e}");
                return ExitCode::from(1);
            }
        }
    }
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("runeward-vmagent serve: {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let helper = std::env::current_exe()
        .map(HelperMode::SelfExec)
        .unwrap_or(HelperMode::InProcess);
    let agent = Agent::new(helper, Box::new(HostPlatform), Reaper::per_child());
    for conn in listener.incoming().flatten() {
        let a = Arc::clone(&agent);
        std::thread::spawn(move || a.serve(conn));
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("runeward-vmagent {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        #[cfg(unix)]
        Some("__run") => code(runeward_vmagent::helper::run(&args[1..])),
        #[cfg(unix)]
        Some("__file") => code(runeward_vmagent::helper::file(&args[1..])),
        #[cfg(unix)]
        Some("serve") => serve(&args[1..]),
        _ => {
            #[cfg(target_os = "linux")]
            if std::process::id() == 1 {
                runeward_vmagent::guest::boot();
            }
            eprintln!(
                "runeward-vmagent: the guest agent runs as PID 1 inside a Rune Box microVM; usage: runeward-vmagent [--version | serve --unix PATH]"
            );
            ExitCode::from(2)
        }
    }
}
