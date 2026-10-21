//! The agent's request handling, driven over a socket pair on the test host
//! (no VM, no identity switching).

#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use runeward_vmagent::proto::{
    self, ExecSpec, Exit, FileAction, FileRequest, InitRequest, Kind, Request, StartRequest,
    StatusResult,
};
use runeward_vmagent::server::{Agent, HelperMode, HostPlatform, Reaper};

fn agent() -> Arc<Agent> {
    Agent::new(
        HelperMode::InProcess,
        Box::new(HostPlatform),
        Reaper::per_child(),
    )
}

/// Opens a connection to `a` and sends `req`.
fn open(a: &Arc<Agent>, req: &Request) -> UnixStream {
    let (host, guest) = UnixStream::pair().expect("pair");
    let a = Arc::clone(a);
    thread::spawn(move || a.serve(guest));
    let mut h = host.try_clone().expect("clone");
    proto::write_frame(
        &mut h,
        Kind::Request,
        &serde_json::to_vec(req).expect("json"),
    )
    .expect("send");
    host
}

/// Reads frames to the terminal one: (stdout, stderr, terminal kind, body).
fn collect(mut s: UnixStream) -> (Vec<u8>, Vec<u8>, Kind, Vec<u8>) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    loop {
        let (k, p) = proto::read_frame(&mut s)
            .expect("read")
            .expect("terminal frame");
        match k {
            Kind::Stdout => out.extend(p),
            Kind::Stderr => err.extend(p),
            k if k.is_terminal() => return (out, err, k, p),
            _ => {}
        }
    }
}

fn init(a: &Arc<Agent>, workdir: &str) {
    let (_, _, k, p) = collect(open(
        a,
        &Request::Init(InitRequest {
            hostname: "sb".into(),
            workdir: workdir.into(),
            env: BTreeMap::from([("FROM_IMAGE".into(), "1".into())]),
            ..InitRequest::default()
        }),
    ));
    assert_eq!(k, Kind::Result, "{}", String::from_utf8_lossy(&p));
}

#[test]
fn exec_streams_and_exit_status() {
    let a = agent();
    let dir = tempfile::tempdir().expect("tempdir");
    init(&a, &dir.path().to_string_lossy());
    let (out, err, k, p) = collect(open(
        &a,
        &Request::Exec(ExecSpec {
            argv: [
                "/bin/sh",
                "-c",
                "echo out:$FROM_IMAGE:$X:$(pwd); echo err >&2; exit 3",
            ]
            .map(String::from)
            .to_vec(),
            env: BTreeMap::from([("X".into(), "y".into())]),
            ..ExecSpec::default()
        }),
    ));
    assert_eq!(k, Kind::Exit);
    let exit: Exit = serde_json::from_slice(&p).expect("exit");
    assert_eq!(exit.code, 3);
    let out = String::from_utf8_lossy(&out);
    let canon = dir.path().canonicalize().expect("canon");
    assert!(
        out.trim() == format!("out:1:y:{}", dir.path().display())
            || out.trim() == format!("out:1:y:{}", canon.display()),
        "{out}"
    );
    assert_eq!(err, b"err\n");

    let (_, err, k, p) = collect(open(
        &a,
        &Request::Exec(ExecSpec {
            argv: vec!["/definitely/not/here".into()],
            ..ExecSpec::default()
        }),
    ));
    assert_eq!(k, Kind::Exit);
    assert_eq!(serde_json::from_slice::<Exit>(&p).expect("exit").code, 127);
    assert!(!err.is_empty());
}

#[test]
fn exec_stdin_and_signals() {
    let a = agent();
    let mut s = open(
        &a,
        &Request::Exec(ExecSpec {
            argv: vec!["cat".into()],
            ..ExecSpec::default()
        }),
    );
    proto::write_frame(&mut s, Kind::Stdin, b"ping").expect("stdin");
    proto::write_frame(&mut s, Kind::StdinEof, b"").expect("eof");
    let (out, _, k, _) = collect(s);
    assert_eq!((out.as_slice(), k), (&b"ping"[..], Kind::Exit));

    let mut s = open(
        &a,
        &Request::Exec(ExecSpec {
            argv: vec!["sleep".into(), "30".into()],
            ..ExecSpec::default()
        }),
    );
    let started = Instant::now();
    s.write_all_frame(Kind::Signal, br#"{"signal":9}"#);
    let (_, _, k, p) = collect(s);
    assert_eq!(k, Kind::Exit);
    let exit: Exit = serde_json::from_slice(&p).expect("exit");
    assert_eq!(exit.signal, Some(9));
    assert!(started.elapsed() < Duration::from_secs(10));
}

trait FrameExt {
    fn write_all_frame(&mut self, k: Kind, p: &[u8]);
}

impl FrameExt for UnixStream {
    fn write_all_frame(&mut self, k: Kind, p: &[u8]) {
        proto::write_frame(self, k, p).expect("frame");
    }
}

#[test]
fn closing_the_stream_kills_the_command() {
    let a = agent();
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("pid");
    let s = open(
        &a,
        &Request::Exec(ExecSpec {
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("echo $$ > {}; exec sleep 60", marker.display()),
            ],
            ..ExecSpec::default()
        }),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid = loop {
        if let Ok(p) = std::fs::read_to_string(&marker)
            && let Ok(pid) = p.trim().parse::<i32>()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "command never started");
        thread::sleep(Duration::from_millis(20));
    };
    drop(s);
    let deadline = Instant::now() + Duration::from_secs(10);
    while nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok() {
        assert!(
            Instant::now() < deadline,
            "process {pid} survived the host going away"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn tty_exec() {
    let a = agent();
    let (out, _, k, p) = collect(open(
        &a,
        &Request::Exec(ExecSpec {
            argv: ["/bin/sh", "-c", "test -t 0 && echo tty:$TERM"]
                .map(String::from)
                .to_vec(),
            tty: true,
            rows: 30,
            cols: 100,
            ..ExecSpec::default()
        }),
    ));
    assert_eq!(k, Kind::Exit);
    assert_eq!(serde_json::from_slice::<Exit>(&p).expect("exit").code, 0);
    assert!(String::from_utf8_lossy(&out).contains("tty:xterm"));
}

#[test]
fn files_and_workspace_tar() {
    let a = agent();
    let dir = tempfile::tempdir().expect("tempdir");
    init(&a, &dir.path().to_string_lossy());
    let mut s = open(
        &a,
        &Request::File(FileRequest {
            action: FileAction::Write,
            path: "sub/hello.txt".into(),
            mode: 0o640,
            user: String::new(),
        }),
    );
    s.write_all_frame(Kind::Stdin, b"hello ");
    s.write_all_frame(Kind::Stdin, b"world");
    s.write_all_frame(Kind::StdinEof, b"");
    let (_, _, k, p) = collect(s);
    assert_eq!(k, Kind::Result, "{}", String::from_utf8_lossy(&p));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sub/hello.txt")).expect("read"),
        "hello world"
    );

    let (out, _, k, _) = collect(open(
        &a,
        &Request::File(FileRequest {
            action: FileAction::Read,
            path: "sub/hello.txt".into(),
            ..FileRequest::default()
        }),
    ));
    assert_eq!((out.as_slice(), k), (&b"hello world"[..], Kind::Result));

    let (tar, _, k, _) = collect(open(
        &a,
        &Request::File(FileRequest {
            action: FileAction::TarOut,
            path: String::new(),
            ..FileRequest::default()
        }),
    ));
    assert_eq!(k, Kind::Result);
    let names: Vec<String> = tar::Archive::new(tar.as_slice())
        .entries()
        .expect("entries")
        .map(|e| {
            e.expect("entry")
                .path()
                .expect("path")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with("sub/hello.txt")),
        "{names:?}"
    );

    let (_, _, k, p) = collect(open(
        &a,
        &Request::File(FileRequest {
            action: FileAction::Read,
            path: "missing".into(),
            ..FileRequest::default()
        }),
    ));
    assert_eq!(k, Kind::Error);
    assert!(String::from_utf8_lossy(&p).contains("missing"));
}

#[test]
fn main_process_status() {
    let a = agent();
    let dir = tempfile::tempdir().expect("tempdir");
    init(&a, &dir.path().to_string_lossy());
    let (_, _, k, _) = collect(open(&a, &Request::Status));
    assert_eq!(k, Kind::Result);
    let (_, _, k, p) = collect(open(
        &a,
        &Request::Start(StartRequest {
            argv: ["/bin/sh", "-c", "exit 4"].map(String::from).to_vec(),
            user: String::new(),
        }),
    ));
    assert_eq!(k, Kind::Result, "{}", String::from_utf8_lossy(&p));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, _, _, p) = collect(open(&a, &Request::Status));
        let st: StatusResult = serde_json::from_slice(&p).expect("status");
        if st.main == "exited" {
            assert_eq!(st.exit.expect("exit").code, 4);
            break;
        }
        assert!(Instant::now() < deadline, "main never exited: {st:?}");
        thread::sleep(Duration::from_millis(50));
    }
    let (_, _, k, _) = collect(open(&a, &Request::Init(InitRequest::default())));
    assert_eq!(k, Kind::Error, "a second init is refused");
}
