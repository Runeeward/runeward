//! Command-line flags parsed like Go's `flag` package: `-name value`,
//! `--name value`, `-name=value` and `--name=value`, stopping at the first
//! non-flag argument or after `--`.

use std::collections::HashMap;

/// Why parsing stopped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FlagError {
    /// `-h` or `-help` was given.
    Help,
    /// A malformed or unknown flag; the message matches Go's.
    Bad(String),
}

/// Parsed string flags and the remaining positional arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Parsed {
    values: HashMap<String, String>,
    pub(crate) args: Vec<String>,
}

impl Parsed {
    /// The flag's value, or `""` when it was not given.
    pub(crate) fn get(&self, name: &str) -> String {
        self.values.get(name).cloned().unwrap_or_default()
    }
}

/// Parses `args` for the string flags named in `known`.
pub(crate) fn parse(known: &[&str], args: &[String]) -> Result<Parsed, FlagError> {
    let mut out = Parsed::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.len() < 2 || !arg.starts_with('-') {
            break;
        }
        i += 1;
        let mut name = &arg[1..];
        if let Some(rest) = name.strip_prefix('-') {
            if rest.is_empty() {
                // "--" ends the flags.
                break;
            }
            name = rest;
        }
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(FlagError::Bad(format!("bad flag syntax: {arg}")));
        }
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (name, None),
        };
        if !known.contains(&name) {
            if name == "h" || name == "help" {
                return Err(FlagError::Help);
            }
            return Err(FlagError::Bad(format!(
                "flag provided but not defined: -{name}"
            )));
        }
        let value = match inline {
            Some(v) => v,
            None => {
                let Some(v) = args.get(i) else {
                    return Err(FlagError::Bad(format!("flag needs an argument: -{name}")));
                };
                i += 1;
                v.clone()
            }
        };
        out.values.insert(name.to_owned(), value);
    }
    out.args = args[i..].to_vec();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn go_flag_forms() {
        let p = parse(
            &["socket", "token", "mode"],
            &args(&[
                "-socket",
                "/s",
                "--token=t",
                "--mode",
                "text",
                "https://x",
                "-socket",
                "y",
            ]),
        )
        .expect("parse");
        assert_eq!(p.get("socket"), "/s");
        assert_eq!(p.get("token"), "t");
        assert_eq!(p.get("mode"), "text");
        assert_eq!(p.get("proxy"), "");
        assert_eq!(p.args, ["https://x", "-socket", "y"]);

        let p = parse(&["a"], &args(&["-a=1", "--", "-a"])).expect("parse");
        assert_eq!((p.get("a"), p.args), ("1".to_owned(), args(&["-a"])));
        let p = parse(&["a"], &args(&["-a", "1", "-a", "2", "-"])).expect("parse");
        assert_eq!((p.get("a"), p.args), ("2".to_owned(), args(&["-"])));
    }

    #[test]
    fn go_flag_errors() {
        assert_eq!(parse(&["a"], &args(&["-h"])), Err(FlagError::Help));
        assert_eq!(parse(&["a"], &args(&["--help"])), Err(FlagError::Help));
        assert_eq!(
            parse(&["a"], &args(&["-b"])),
            Err(FlagError::Bad("flag provided but not defined: -b".into()))
        );
        assert_eq!(
            parse(&["a"], &args(&["-a"])),
            Err(FlagError::Bad("flag needs an argument: -a".into()))
        );
        assert_eq!(
            parse(&["a"], &args(&["---a"])),
            Err(FlagError::Bad("bad flag syntax: ---a".into()))
        );
    }
}
