//! The Firecracker guest's initramfs: just the agent as `/init`.
//!
//! A `newc` cpio archive written directly (no `cpio` tool, no root: the
//! kernel creates the `/dev/console` node while unpacking). The agent
//! never lives on the image disk, so any image boots unmodified.

/// One archive member.
struct Member<'a> {
    name: &'a str,
    mode: u32,
    rdev: (u32, u32),
    data: &'a [u8],
}

fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn push(out: &mut Vec<u8>, ino: u32, m: &Member<'_>) {
    let fields = [
        ino,
        m.mode,
        0,
        0,
        if m.mode & 0o040_000 != 0 { 2 } else { 1 },
        0,
        m.data.len() as u32,
        0,
        0,
        m.rdev.0,
        m.rdev.1,
        m.name.len() as u32 + 1,
        0,
    ];
    out.extend_from_slice(b"070701");
    for f in fields {
        out.extend_from_slice(format!("{f:08X}").as_bytes());
    }
    out.extend_from_slice(m.name.as_bytes());
    out.push(0);
    pad4(out);
    out.extend_from_slice(m.data);
    pad4(out);
}

/// The initramfs with `agent` as `/init`, the mount points the agent uses
/// before its first mount, and `/dev/console`.
pub(crate) fn build(agent: &[u8]) -> Vec<u8> {
    let dir = 0o040_755;
    let members = [
        Member {
            name: "dev",
            mode: dir,
            rdev: (0, 0),
            data: &[],
        },
        Member {
            name: "dev/console",
            mode: 0o020_600,
            rdev: (5, 1),
            data: &[],
        },
        Member {
            name: "proc",
            mode: dir,
            rdev: (0, 0),
            data: &[],
        },
        Member {
            name: "sys",
            mode: dir,
            rdev: (0, 0),
            data: &[],
        },
        Member {
            name: "newroot",
            mode: dir,
            rdev: (0, 0),
            data: &[],
        },
        Member {
            name: "init",
            mode: 0o100_755,
            rdev: (0, 0),
            data: agent,
        },
    ];
    let mut out = Vec::with_capacity(agent.len() + 1024);
    for (i, m) in members.iter().enumerate() {
        push(&mut out, i as u32 + 1, m);
    }
    push(
        &mut out,
        0,
        &Member {
            name: "TRAILER!!!",
            mode: 0,
            rdev: (0, 0),
            data: &[],
        },
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a newc archive back into (name, mode, rdev major, data).
    fn parse(mut b: &[u8]) -> Vec<(String, u32, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let total = b.len();
        loop {
            assert_eq!(&b[..6], b"070701");
            let field = |i: usize| {
                let s = std::str::from_utf8(&b[6 + i * 8..14 + i * 8]).expect("hex");
                u32::from_str_radix(s, 16).expect("hex")
            };
            let (mode, size, rmaj, namesize) =
                (field(1), field(6) as usize, field(9), field(11) as usize);
            let name = String::from_utf8(b[110..110 + namesize - 1].to_vec()).expect("name");
            let mut off = 110 + namesize;
            off += (4 - (total - b.len() + off) % 4) % 4;
            let data = b[off..off + size].to_vec();
            off += size;
            off += (4 - (total - b.len() + off) % 4) % 4;
            b = &b[off..];
            if name == "TRAILER!!!" {
                assert!(b.is_empty());
                return out;
            }
            out.push((name, mode, rmaj, data));
        }
    }

    #[test]
    fn newc_layout() {
        let img = build(b"\x7fELF-agent");
        assert_eq!(img.len() % 4, 0);
        let members = parse(&img);
        let names: Vec<&str> = members.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(
            names,
            ["dev", "dev/console", "proc", "sys", "newroot", "init"]
        );
        let console = &members[1];
        assert_eq!((console.1, console.2), (0o020_600, 5));
        let init = &members[5];
        assert_eq!(
            (init.1, init.3.as_slice()),
            (0o100_755, &b"\x7fELF-agent"[..])
        );
    }
}
