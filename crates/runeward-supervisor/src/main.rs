//! `runeward-supervisor`: see the library docs for behaviour and formats.

use std::process::ExitCode;

use runeward_supervisor::{EXIT_CONFIG, EXIT_USAGE, USAGE, load_config, parse_args};

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("runeward-supervisor: {e}\n{USAGE}");
            return exit(EXIT_USAGE);
        }
    };
    if args.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.version {
        println!("runeward-supervisor {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if !cfg!(target_os = "linux") {
        eprintln!(
            "runeward-supervisor: refusing to start: Landlock and seccomp confinement needs Linux; this binary does not run agents on {}",
            std::env::consts::OS
        );
        return exit(runeward_supervisor::EXIT_UNSUPPORTED);
    }
    if args.mode == runeward_supervisor::Mode::AttributionHelper {
        return exit(attribution_helper());
    }
    let (config, config_path) = match load_config(&args, |k| std::env::var(k).ok()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runeward-supervisor: refusing to start: {e}");
            return exit(EXIT_CONFIG);
        }
    };
    exit(run(runeward_supervisor::Invocation {
        mode: args.mode,
        config,
        config_path,
    }))
}

#[cfg(target_os = "linux")]
fn run(inv: runeward_supervisor::Invocation) -> i32 {
    runeward_supervisor::linux::run(inv)
}

#[cfg(target_os = "linux")]
fn attribution_helper() -> i32 {
    runeward_supervisor::linux::attribution::helper_main()
}

#[cfg(not(target_os = "linux"))]
fn attribution_helper() -> i32 {
    runeward_supervisor::EXIT_UNSUPPORTED
}

#[cfg(not(target_os = "linux"))]
fn run(_: runeward_supervisor::Invocation) -> i32 {
    runeward_supervisor::EXIT_UNSUPPORTED
}
