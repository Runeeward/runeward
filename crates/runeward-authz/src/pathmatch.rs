//! A byte-for-byte port of Go's `path.Match`, which profile globs use.
//!
//! `*` matches any run of non-`/` bytes, `?` one non-`/` character, `[...]`
//! a character class (`^` negates, `a-z` ranges, `\` escapes) and `\c` a
//! literal `c`. A malformed pattern is an error, which callers treat as "no
//! match".

/// The pattern is malformed (Go's `path.ErrBadPattern`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BadPattern;

/// Go's `utf8.RuneError`.
const RUNE_ERROR: u32 = 0xFFFD;

/// Reports whether `name` matches the shell pattern `pattern`.
pub(crate) fn path_match(pattern: &str, name: &str) -> Result<bool, BadPattern> {
    let mut pattern = pattern.as_bytes();
    let mut name = name.as_bytes();
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            // Trailing * matches rest of string unless it has a /.
            return Ok(!name.contains(&b'/'));
        }
        // Look for match at current position. If this is the last chunk, the
        // name must be exhausted, otherwise the star may still match.
        if let Some(t) = match_chunk(chunk, name)?
            && (t.is_empty() || !pattern.is_empty())
        {
            name = t;
            continue;
        }
        if star {
            // Look for match skipping i+1 bytes. Cannot skip /.
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                if let Some(t) = match_chunk(chunk, &name[i + 1..])? {
                    // If this is the last chunk, the name must be exhausted.
                    if !pattern.is_empty() || t.is_empty() {
                        name = t;
                        continue 'pattern;
                    }
                }
                i += 1;
            }
        }
        // Before returning false with no error, check that the remainder of
        // the pattern is syntactically valid.
        while !pattern.is_empty() {
            let (_, chunk, rest) = scan_chunk(pattern);
            pattern = rest;
            match_chunk(chunk, b"")?;
        }
        return Ok(false);
    }
    Ok(name.is_empty())
}

/// Gets the next segment of `pattern`: a non-star string possibly preceded by
/// a star. Returns `(star, chunk, rest)`.
fn scan_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while pattern.first() == Some(&b'*') {
        pattern = &pattern[1..];
        star = true;
    }
    let mut in_range = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            // Error check handled in match_chunk: bad pattern.
            b'\\' if i + 1 < pattern.len() => i += 1,
            b'[' => in_range = true,
            b']' => in_range = false,
            b'*' if !in_range => break,
            _ => {}
        }
        i += 1;
    }
    (star, &pattern[..i], &pattern[i..])
}

/// Checks whether `chunk` matches the beginning of `s`, returning the
/// remainder of `s` on a match. `chunk` is all single-character operators:
/// literals, character classes and `?`.
fn match_chunk<'a>(mut chunk: &[u8], mut s: &'a [u8]) -> Result<Option<&'a [u8]>, BadPattern> {
    // After the match fails, keep processing the chunk to check that the
    // pattern is well-formed, but stop reading s.
    let mut failed = false;
    while let Some(&c) = chunk.first() {
        if !failed && s.is_empty() {
            failed = true;
        }
        match c {
            b'[' => {
                let mut r = 0;
                if !failed {
                    let (rune, n) = decode_rune(s);
                    r = rune;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let negated = chunk.first() == Some(&b'^');
                if negated {
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if chunk.first() == Some(&b']') && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = get_esc(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if chunk.first() == Some(&b'-') {
                        let (h, rest) = get_esc(&chunk[1..])?;
                        hi = h;
                        chunk = rest;
                    }
                    if lo <= r && r <= hi {
                        matched = true;
                    }
                    nrange += 1;
                }
                if matched == negated {
                    failed = true;
                }
            }
            b'?' => {
                if !failed {
                    if s[0] == b'/' {
                        failed = true;
                    }
                    let (_, n) = decode_rune(s);
                    s = &s[n..];
                }
                chunk = &chunk[1..];
            }
            _ => {
                if c == b'\\' {
                    chunk = &chunk[1..];
                    if chunk.is_empty() {
                        return Err(BadPattern);
                    }
                }
                if !failed {
                    if chunk[0] != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    Ok(if failed { None } else { Some(s) })
}

/// Gets a possibly-escaped character from `chunk`, for a character class.
fn get_esc(mut chunk: &[u8]) -> Result<(u32, &[u8]), BadPattern> {
    match chunk.first() {
        None | Some(b'-') | Some(b']') => return Err(BadPattern),
        Some(b'\\') => {
            chunk = &chunk[1..];
            if chunk.is_empty() {
                return Err(BadPattern);
            }
        }
        Some(_) => {}
    }
    let (r, n) = decode_rune(chunk);
    if r == RUNE_ERROR && n == 1 {
        return Err(BadPattern);
    }
    let rest = &chunk[n..];
    if rest.is_empty() {
        return Err(BadPattern);
    }
    Ok((r, rest))
}

/// Decodes the first UTF-8 character of `s` like Go's
/// `utf8.DecodeRuneInString`: invalid input yields `(RUNE_ERROR, 1)` and
/// empty input `(RUNE_ERROR, 0)`.
fn decode_rune(s: &[u8]) -> (u32, usize) {
    for n in 1..=s.len().min(4) {
        if let Ok(text) = std::str::from_utf8(&s[..n])
            && let Some(ch) = text.chars().next()
        {
            return (u32::from(ch), n);
        }
    }
    (RUNE_ERROR, usize::from(!s.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go's `path` package match table.
    #[test]
    fn go_match_table() {
        let bad = Err(BadPattern);
        let cases: &[(&str, &str, Result<bool, BadPattern>)] = &[
            ("abc", "abc", Ok(true)),
            ("*", "abc", Ok(true)),
            ("*c", "abc", Ok(true)),
            ("a*", "a", Ok(true)),
            ("a*", "abc", Ok(true)),
            ("a*", "ab/c", Ok(false)),
            ("a*/b", "abc/b", Ok(true)),
            ("a*/b", "a/c/b", Ok(false)),
            ("a*b*c*d*e*/f", "axbxcxdxe/f", Ok(true)),
            ("a*b*c*d*e*/f", "axbxcxdxexxx/f", Ok(true)),
            ("a*b*c*d*e*/f", "axbxcxdxe/xxx/f", Ok(false)),
            ("a*b*c*d*e*/f", "axbxcxdxexxx/fff", Ok(false)),
            ("a*b?c*x", "abxbbxdbxebxczzx", Ok(true)),
            ("a*b?c*x", "abxbbxdbxebxczzy", Ok(false)),
            ("ab[c]", "abc", Ok(true)),
            ("ab[b-d]", "abc", Ok(true)),
            ("ab[e-g]", "abc", Ok(false)),
            ("ab[^c]", "abc", Ok(false)),
            ("ab[^b-d]", "abc", Ok(false)),
            ("ab[^e-g]", "abc", Ok(true)),
            ("a\\*b", "a*b", Ok(true)),
            ("a\\*b", "ab", Ok(false)),
            ("a?b", "a☺b", Ok(true)),
            ("a[^a]b", "a☺b", Ok(true)),
            ("a???b", "a☺b", Ok(false)),
            ("a[^a][^a][^a]b", "a☺b", Ok(false)),
            ("[a-ζ]*", "α", Ok(true)),
            ("*[a-ζ]", "A", Ok(false)),
            ("a?b", "a/b", Ok(false)),
            ("a*b", "a/b", Ok(false)),
            ("[\\]a]", "]", Ok(true)),
            ("[\\-]", "-", Ok(true)),
            ("[x\\-]", "x", Ok(true)),
            ("[x\\-]", "-", Ok(true)),
            ("[x\\-]", "z", Ok(false)),
            ("[\\-x]", "x", Ok(true)),
            ("[\\-x]", "-", Ok(true)),
            ("[\\-x]", "a", Ok(false)),
            ("[]a]", "]", bad),
            ("[-]", "-", bad),
            ("[x-]", "x", bad),
            ("[x-]", "-", bad),
            ("[x-]", "z", bad),
            ("[-x]", "x", bad),
            ("[-x]", "-", bad),
            ("[-x]", "a", bad),
            ("\\", "a", bad),
            ("[a-b-c]", "a", bad),
            ("[", "a", bad),
            ("[^", "a", bad),
            ("[^bc", "a", bad),
            ("a[", "a", bad),
            ("a[", "ab", bad),
            ("a[", "x", bad),
            ("a/b[", "x", bad),
            ("*x", "xxx", Ok(true)),
        ];
        for (pattern, name, want) in cases {
            assert_eq!(
                path_match(pattern, name),
                *want,
                "path_match({pattern:?}, {name:?})"
            );
        }
    }
}
