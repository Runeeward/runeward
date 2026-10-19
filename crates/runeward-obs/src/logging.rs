//! The `tracing` subscriber for the operator-facing services.

use tracing::Dispatch;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Selects "json" or "text" log output (default text).
pub const ENV_LOG_FORMAT: &str = "RUNEWARD_LOG_FORMAT";
/// Selects debug/info/warn/error (default info).
pub const ENV_LOG_LEVEL: &str = "RUNEWARD_LOG_LEVEL";

/// The log line encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// Parses a level name: debug, warn/warning, error; anything else is info.
pub fn parse_level(s: &str) -> LevelFilter {
    match s.trim().to_lowercase().as_str() {
        "debug" => LevelFilter::DEBUG,
        "warn" | "warning" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    }
}

/// Parses a format name: "json" (any case) is JSON, anything else is text.
pub fn parse_format(s: &str) -> LogFormat {
    if s.trim().eq_ignore_ascii_case("json") {
        LogFormat::Json
    } else {
        LogFormat::Text
    }
}

/// Builds the subscriber from [`ENV_LOG_FORMAT`] and [`ENV_LOG_LEVEL`],
/// writing to stderr.
pub fn dispatch_from_lookup<F>(lookup: F) -> Dispatch
where
    F: Fn(&str) -> Option<String>,
{
    let format = parse_format(&lookup(ENV_LOG_FORMAT).unwrap_or_default());
    let level = parse_level(&lookup(ENV_LOG_LEVEL).unwrap_or_default());
    dispatch(format, level, std::io::stderr)
}

/// Builds a subscriber with an explicit format, level and writer.
pub fn dispatch<W>(format: LogFormat, level: LevelFilter, writer: W) -> Dispatch
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(writer)
        .with_ansi(false);
    match format {
        LogFormat::Json => Dispatch::new(builder.json().flatten_event(true).finish()),
        LogFormat::Text => Dispatch::new(builder.finish()),
    }
}

/// Installs the environment-configured subscriber as the global default.
/// Returns false if a global subscriber was already set.
pub fn init_logging() -> bool {
    tracing::dispatcher::set_global_default(dispatch_from_lookup(|k| std::env::var(k).ok())).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[test]
    fn level_parsing() {
        assert_eq!(parse_level("debug"), LevelFilter::DEBUG);
        assert_eq!(parse_level(" WARN "), LevelFilter::WARN);
        assert_eq!(parse_level("warning"), LevelFilter::WARN);
        assert_eq!(parse_level("error"), LevelFilter::ERROR);
        assert_eq!(parse_level("info"), LevelFilter::INFO);
        assert_eq!(parse_level(""), LevelFilter::INFO);
        assert_eq!(parse_level("trace"), LevelFilter::INFO);
    }

    #[test]
    fn format_parsing() {
        assert_eq!(parse_format("json"), LogFormat::Json);
        assert_eq!(parse_format(" JSON "), LogFormat::Json);
        assert_eq!(parse_format("text"), LogFormat::Text);
        assert_eq!(parse_format(""), LogFormat::Text);
    }

    #[test]
    fn json_output_honours_level() {
        let buf = Buf::default();
        let d = dispatch(LogFormat::Json, LevelFilter::WARN, buf.clone());
        tracing::dispatcher::with_default(&d, || {
            tracing::info!("hidden");
            tracing::warn!(seq = 7, "shown");
        });
        let out = buf.text();
        assert!(!out.contains("hidden"));
        let line: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(line["level"], "WARN");
        assert_eq!(line["message"], "shown");
        assert_eq!(line["seq"], 7);
    }

    #[test]
    fn text_output_is_plain() {
        let buf = Buf::default();
        let d = dispatch(LogFormat::Text, LevelFilter::DEBUG, buf.clone());
        tracing::dispatcher::with_default(&d, || tracing::debug!(tool = "shell", "hello"));
        let out = buf.text();
        assert!(out.contains("DEBUG"), "{out}");
        assert!(out.contains("hello tool=\"shell\""), "{out}");
        assert!(!out.contains('\u{1b}'), "no ANSI escapes: {out:?}");
    }
}
