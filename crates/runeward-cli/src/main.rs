//! `runeward`: policy, approvals, and signed audit for AI agents.

use std::io::Write;

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: start async runtime: {e}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(runeward_cli::execute(std::env::args_os().skip(1).collect()));
    let _ = std::io::stdout().flush();
    // Exit without dropping the runtime: a pending blocking read of stdin
    // (an attached terminal) must not hold the process open.
    std::process::exit(code);
}
