//! Serving the protocol: one thread per host connection.
//!
//! Commands never run in the agent's own process. In the guest every
//! command, and every file operation, goes through the agent's helper mode
//! (`/proc/self/exe __run|__file ...`), which switches to the target
//! identity before it touches anything, so a file operation can never be
//! redirected by a link the sandbox planted. [`HelperMode::InProcess`]
//! skips the helper (and identity switching) for tests on a host.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal as NixSignal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;

use crate::fileops;
use crate::proto::{
    self, ErrorBody, ExecSpec, Exit, FileAction, FileRequest, HelloResult, InitRequest, Kind,
    PROTOCOL_VERSION, ProbeResult, Request, Resize, Signal, StartRequest, Started, StatusResult,
};
use crate::users::{self, Identity};

/// How long output may keep arriving after a process exited (background
/// children holding its pipes do not hold the call open forever).
const OUTPUT_GRACE: Duration = Duration::from_secs(2);

/// The default `PATH` (Docker's).
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How commands and file operations are launched.
#[derive(Debug, Clone)]
pub enum HelperMode {
    /// Through the agent binary's helper mode, which switches identity
    /// first (the guest).
    SelfExec(PathBuf),
    /// Directly, as the agent's own identity (tests on a host).
    InProcess,
}

/// What differs between the guest and a test host.
pub trait Platform: Send + Sync + fmt::Debug {
    /// Mounts the sandbox root and workspace and enters it.
    fn init(&self, req: &InitRequest) -> Result<(), String> {
        let _ = req;
        Ok(())
    }

    /// Makes the root read-only once the sandbox is staged.
    fn seal(&self) -> Result<(), String> {
        Ok(())
    }

    /// Collects the isolation probe.
    fn probe(&self) -> String {
        crate::probe::collect(Path::new("/"))
    }

    /// Stops everything and powers the guest off.
    fn shutdown(&self) {}

    /// The root account files are read from.
    fn root(&self) -> PathBuf {
        PathBuf::from("/")
    }
}

/// The test-host platform: nothing to mount, nothing to power off.
#[derive(Debug, Default)]
pub struct HostPlatform;

impl Platform for HostPlatform {}

/// Collects exit statuses. In the guest the agent is PID 1, so it must reap
/// every orphan; one thread waits for any child and hands statuses to
/// whoever registered the pid. Elsewhere each child is waited for on its
/// own.
#[derive(Debug)]
pub struct Reaper {
    global: bool,
    waiters: Mutex<HashMap<i32, mpsc::Sender<Exit>>>,
    early: Mutex<HashMap<i32, (Exit, Instant)>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Reaper {
    /// Waits for each child separately (not PID 1).
    pub fn per_child() -> Arc<Self> {
        Arc::new(Self {
            global: false,
            waiters: Mutex::new(HashMap::new()),
            early: Mutex::new(HashMap::new()),
        })
    }

    /// Reaps every child of the process (PID 1).
    pub fn global() -> Arc<Self> {
        let r = Arc::new(Self {
            global: true,
            waiters: Mutex::new(HashMap::new()),
            early: Mutex::new(HashMap::new()),
        });
        let me = Arc::clone(&r);
        thread::spawn(move || {
            loop {
                match waitpid(Pid::from_raw(-1), None) {
                    Ok(WaitStatus::Exited(pid, code)) => {
                        me.deliver(pid.as_raw(), Exit { code, signal: None })
                    }
                    Ok(WaitStatus::Signaled(pid, sig, _)) => me.deliver(
                        pid.as_raw(),
                        Exit {
                            code: -1,
                            signal: Some(sig as i32),
                        },
                    ),
                    Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        r
    }

    fn deliver(&self, pid: i32, exit: Exit) {
        if let Some(tx) = lock(&self.waiters).remove(&pid) {
            let _ = tx.send(exit);
            return;
        }
        let mut early = lock(&self.early);
        // Orphans nobody waits for: drop the stale ones.
        early.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(60));
        early.insert(pid, (exit, Instant::now()));
    }

    /// Returns a receiver for `child`'s exit.
    pub fn watch(&self, mut child: std::process::Child) -> mpsc::Receiver<Exit> {
        let (tx, rx) = mpsc::channel();
        let pid = child.id() as i32;
        if self.global {
            let mut waiters = lock(&self.waiters);
            if let Some((exit, _)) = lock(&self.early).remove(&pid) {
                let _ = tx.send(exit);
            } else {
                waiters.insert(pid, tx);
            }
            // The global thread reaps it; `Child` is only dropped.
            return rx;
        }
        thread::spawn(move || {
            let exit = match child.wait() {
                Ok(st) => exit_of(st),
                Err(_) => Exit {
                    code: -1,
                    signal: None,
                },
            };
            let _ = tx.send(exit);
        });
        rx
    }
}

fn exit_of(st: std::process::ExitStatus) -> Exit {
    use std::os::unix::process::ExitStatusExt;
    match st.code() {
        Some(code) => Exit { code, signal: None },
        None => Exit {
            code: -1,
            signal: st.signal(),
        },
    }
}

/// The agent.
#[derive(Debug)]
pub struct Agent {
    helper: HelperMode,
    platform: Box<dyn Platform>,
    reaper: Arc<Reaper>,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    init: Option<InitRequest>,
    main: Option<Arc<Mutex<Option<Exit>>>>,
}

/// Frames sent from several threads on one connection.
#[derive(Clone)]
struct Out(Arc<Mutex<UnixStream>>);

impl Out {
    fn send(&self, kind: Kind, payload: &[u8]) -> io::Result<()> {
        proto::write_frame(&mut *lock(&self.0), kind, payload)
    }

    fn json<T: serde::Serialize>(&self, kind: Kind, body: &T) -> io::Result<()> {
        let mut s = lock(&self.0);
        s.write_all(&proto::encode_json(kind, body))?;
        s.flush()
    }

    fn error(&self, message: impl Into<String>) {
        let _ = self.json(
            Kind::Error,
            &ErrorBody {
                message: message.into(),
            },
        );
    }

    fn close(&self) {
        let _ = lock(&self.0).shutdown(Shutdown::Both);
    }
}

/// Reads stdin frames as a byte stream: EOF at [`Kind::StdinEof`], an
/// error when the host went away (the operation is cancelled).
struct FrameReader {
    conn: UnixStream,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl Read for FrameReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            if self.eof {
                return Ok(0);
            }
            match proto::read_frame(&mut self.conn)? {
                Some((Kind::Stdin, data)) => {
                    self.buf = data;
                    self.pos = 0;
                }
                Some((Kind::StdinEof, _)) => self.eof = true,
                Some(_) => {}
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "host closed the stream",
                    ));
                }
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Writes bytes as stdout frames.
struct FrameWriter(Out);

impl Write for FrameWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        for chunk in data.chunks(32 * 1024) {
            self.0.send(Kind::Stdout, chunk)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Copies `r` into frames of `kind` until EOF; signals `done` after.
fn pump(mut r: impl Read, kind: Kind, out: Out, done: mpsc::Sender<()>) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.send(kind, &buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = done.send(());
}

/// A resolved launch: program, arguments, environment and identity.
#[derive(Debug, Clone)]
struct Launch {
    program: OsString,
    args: Vec<OsString>,
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    ident: Option<Identity>,
}

impl Launch {
    fn std(&self) -> Command {
        let mut c = Command::new(&self.program);
        c.args(&self.args).env_clear().envs(&self.env);
        if let Some(d) = &self.cwd {
            c.current_dir(d);
        }
        if let Some(id) = &self.ident {
            c.uid(id.uid).gid(id.gid);
        }
        c
    }

    fn pty(&self) -> pty_process::blocking::Command {
        let mut c = pty_process::blocking::Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .envs(&self.env);
        if let Some(d) = &self.cwd {
            c = c.current_dir(d);
        }
        if let Some(id) = &self.ident {
            c = c.uid(id.uid).gid(id.gid);
        }
        c
    }
}

fn kill_group(pid: i32, sig: i32) {
    if pid <= 1 {
        return;
    }
    if let Ok(s) = NixSignal::try_from(sig) {
        let _ = signal::killpg(Pid::from_raw(pid), s);
    }
}

/// Waits for `n` completions on `rx` until `deadline`.
fn wait_n(rx: &mpsc::Receiver<()>, n: usize, grace: Duration) {
    let deadline = Instant::now() + grace;
    for _ in 0..n {
        let left = deadline.saturating_duration_since(Instant::now());
        if rx.recv_timeout(left).is_err() {
            return;
        }
    }
}

impl Agent {
    /// A new agent.
    pub fn new(helper: HelperMode, platform: Box<dyn Platform>, reaper: Arc<Reaper>) -> Arc<Self> {
        Arc::new(Self {
            helper,
            platform,
            reaper,
            state: Mutex::new(State::default()),
        })
    }

    fn init_req(&self) -> InitRequest {
        lock(&self.state).init.clone().unwrap_or_default()
    }

    /// Serves one host connection to completion.
    pub fn serve(self: &Arc<Self>, conn: UnixStream) {
        let Ok(mut reader) = conn.try_clone() else {
            return;
        };
        let out = Out(Arc::new(Mutex::new(conn)));
        let req = match proto::read_frame(&mut reader) {
            Ok(Some((Kind::Request, body))) => match serde_json::from_slice::<Request>(&body) {
                Ok(r) => r,
                Err(e) => {
                    out.error(format!("bad request: {e}"));
                    out.close();
                    return;
                }
            },
            Ok(Some((k, _))) => {
                out.error(format!("expected a request frame, got {k:?}"));
                out.close();
                return;
            }
            Ok(None) | Err(_) => return,
        };
        match req {
            Request::Hello => {
                let initialized = lock(&self.state).init.is_some();
                let _ = out.json(
                    Kind::Result,
                    &HelloResult {
                        protocol: PROTOCOL_VERSION,
                        version: env!("CARGO_PKG_VERSION").into(),
                        initialized,
                    },
                );
            }
            Request::Init(r) => match self.init(r) {
                Ok(()) => {
                    let _ = out.json(Kind::Result, &serde_json::json!({}));
                }
                Err(e) => out.error(e),
            },
            Request::Probe => {
                let _ = out.json(
                    Kind::Result,
                    &ProbeResult {
                        output: self.platform.probe(),
                    },
                );
            }
            Request::Start(r) => match self.start(r) {
                Ok(pid) => {
                    let _ = out.json(Kind::Result, &Started { pid });
                }
                Err(e) => out.error(e),
            },
            Request::Exec(spec) => self.exec(spec, reader, &out),
            Request::File(r) => self.file(r, reader, &out),
            Request::Status => {
                let main = lock(&self.state).main.clone();
                let res = match main {
                    None => StatusResult {
                        main: "none".into(),
                        exit: None,
                    },
                    Some(m) => match *lock(&m) {
                        None => StatusResult {
                            main: "running".into(),
                            exit: None,
                        },
                        Some(e) => StatusResult {
                            main: "exited".into(),
                            exit: Some(e),
                        },
                    },
                };
                let _ = out.json(Kind::Result, &res);
            }
            Request::Shutdown => {
                let _ = out.json(Kind::Result, &serde_json::json!({}));
                out.close();
                self.platform.shutdown();
            }
        }
        out.close();
    }

    fn init(&self, r: InitRequest) -> Result<(), String> {
        let mut st = lock(&self.state);
        if st.init.is_some() {
            return Err("already initialized".into());
        }
        self.platform.init(&r)?;
        st.init = Some(r);
        Ok(())
    }

    fn identity(&self, user: &str) -> Result<Identity, String> {
        let init = self.init_req();
        let spec = if user.trim().is_empty() {
            init.user.as_str()
        } else {
            user
        };
        users::resolve(spec, &self.platform.root())
    }

    /// The environment a process starts with.
    fn env_for(
        &self,
        ident: &Identity,
        extra: &BTreeMap<String, String>,
        tty: bool,
    ) -> BTreeMap<String, String> {
        let init = self.init_req();
        let mut env = init.env.clone();
        env.entry("PATH".into())
            .or_insert_with(|| DEFAULT_PATH.into());
        env.entry("HOME".into())
            .or_insert_with(|| ident.home.clone());
        if !init.hostname.is_empty() {
            env.entry("HOSTNAME".into())
                .or_insert_with(|| init.hostname.clone());
        }
        if tty {
            env.entry("TERM".into()).or_insert_with(|| "xterm".into());
        }
        env.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
        env
    }

    /// Resolves a guest path against the workspace.
    fn resolve_path(&self, p: &str) -> PathBuf {
        if p.starts_with('/') {
            return PathBuf::from(p);
        }
        let wd = self.init_req().workdir;
        let base = if wd.is_empty() { "/".to_owned() } else { wd };
        Path::new(&base).join(p)
    }

    fn am_root() -> bool {
        nix::unistd::geteuid().is_root()
    }

    /// The launch for `argv` as `ident` in `cwd`.
    fn launch(
        &self,
        argv: &[String],
        ident: &Identity,
        cwd: &Path,
        env: BTreeMap<String, String>,
    ) -> Launch {
        match &self.helper {
            HelperMode::SelfExec(exe) => {
                let mut args: Vec<OsString> = vec!["__run".into()];
                args.extend(
                    crate::helper::identity_args(ident)
                        .into_iter()
                        .map(OsString::from),
                );
                args.extend(["--cwd".into(), cwd.as_os_str().to_owned(), "--".into()]);
                args.extend(argv.iter().map(OsString::from));
                Launch {
                    program: exe.as_os_str().to_owned(),
                    args,
                    env,
                    cwd: None,
                    ident: None,
                }
            }
            HelperMode::InProcess => Launch {
                program: argv[0].clone().into(),
                args: argv[1..].iter().map(OsString::from).collect(),
                env,
                cwd: Some(cwd.to_path_buf()),
                ident: (Self::am_root() && ident.uid != 0).then(|| ident.clone()),
            },
        }
    }

    fn start(&self, r: StartRequest) -> Result<i32, String> {
        if r.argv.is_empty() {
            return Err("start: empty argv".into());
        }
        let init = self.init_req();
        if lock(&self.state).main.is_some() {
            return Err("start: the main process already started".into());
        }
        if init.read_only {
            self.platform.seal()?;
        }
        let ident = self.identity(&r.user)?;
        let env = self.env_for(&ident, &BTreeMap::new(), false);
        let cwd = PathBuf::from(if init.workdir.is_empty() {
            "/"
        } else {
            &init.workdir
        });
        let mut cmd = self.launch(&r.argv, &ident, &cwd, env).std();
        cmd.stdin(Stdio::null()).process_group(0);
        let child = cmd
            .spawn()
            .map_err(|e| format!("start {:?}: {e}", r.argv[0]))?;
        let pid = child.id() as i32;
        let slot = Arc::new(Mutex::new(None));
        lock(&self.state).main = Some(Arc::clone(&slot));
        let rx = self.reaper.watch(child);
        thread::spawn(move || {
            if let Ok(e) = rx.recv() {
                eprintln!("runeward-vmagent: main process {pid} exited: {e:?}");
                *lock(&slot) = Some(e);
            }
        });
        Ok(pid)
    }

    fn exec(&self, spec: ExecSpec, reader: UnixStream, out: &Out) {
        if spec.argv.is_empty() {
            out.error("exec: empty argv");
            return;
        }
        let ident = match self.identity(&spec.user) {
            Ok(i) => i,
            Err(e) => {
                out.error(e);
                return;
            }
        };
        let env = self.env_for(&ident, &spec.env, spec.tty);
        let cwd = if spec.workdir.is_empty() {
            let wd = self.init_req().workdir;
            PathBuf::from(if wd.is_empty() { "/".to_owned() } else { wd })
        } else {
            self.resolve_path(&spec.workdir)
        };
        let launch = self.launch(&spec.argv, &ident, &cwd, env);
        if spec.tty {
            self.exec_tty(&spec, &launch, reader, out);
        } else {
            self.exec_pipes(&spec, &launch, reader, out);
        }
    }

    /// Reports a command that could not be started the way a container
    /// engine does: a message on stderr and status 127 (not found) or 126.
    fn not_started(out: &Out, argv0: &str, e: &io::Error) {
        let _ = out.send(Kind::Stderr, format!("exec {argv0:?}: {e}\n").as_bytes());
        let code = if e.kind() == io::ErrorKind::NotFound {
            127
        } else {
            126
        };
        let _ = out.json(Kind::Exit, &Exit { code, signal: None });
    }

    /// Handles host frames for a running process: stdin, signals, resizes;
    /// the host going away kills the process group.
    fn control_loop(
        mut reader: UnixStream,
        pid: i32,
        mut stdin: Option<Box<dyn Write + Send>>,
        on_resize: impl Fn(Resize),
        finished: Arc<AtomicBool>,
    ) {
        loop {
            match proto::read_frame(&mut reader) {
                Ok(Some((Kind::Stdin, data))) => {
                    if let Some(w) = stdin.as_mut()
                        && (w.write_all(&data).is_err() || w.flush().is_err())
                    {
                        stdin = None;
                    }
                }
                Ok(Some((Kind::StdinEof, _))) => stdin = None,
                Ok(Some((Kind::Signal, body))) => {
                    if let Ok(s) = serde_json::from_slice::<Signal>(&body) {
                        kill_group(pid, s.signal);
                    }
                }
                Ok(Some((Kind::Resize, body))) => {
                    if let Ok(r) = serde_json::from_slice::<Resize>(&body) {
                        on_resize(r);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    if !finished.load(Ordering::SeqCst) {
                        kill_group(pid, libc_sigkill());
                    }
                    return;
                }
            }
        }
    }

    fn exec_pipes(&self, spec: &ExecSpec, launch: &Launch, reader: UnixStream, out: &Out) {
        let mut cmd = launch.std();
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                Self::not_started(out, &spec.argv[0], &e);
                return;
            }
        };
        let pid = child.id() as i32;
        let _ = out.json(Kind::Started, &Started { pid });
        let stdin = child
            .stdin
            .take()
            .map(|w| Box::new(w) as Box<dyn Write + Send>);
        let (done_tx, done_rx) = mpsc::channel();
        let mut pumps = 0;
        if let Some(r) = child.stdout.take() {
            let (o, d) = (out.clone(), done_tx.clone());
            thread::spawn(move || pump(r, Kind::Stdout, o, d));
            pumps += 1;
        }
        if let Some(r) = child.stderr.take() {
            let (o, d) = (out.clone(), done_tx.clone());
            thread::spawn(move || pump(r, Kind::Stderr, o, d));
            pumps += 1;
        }
        let exit_rx = self.reaper.watch(child);
        let finished = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&finished);
        thread::spawn(move || Self::control_loop(reader, pid, stdin, |_| {}, f));
        let exit = exit_rx.recv().unwrap_or(Exit {
            code: -1,
            signal: None,
        });
        finished.store(true, Ordering::SeqCst);
        wait_n(&done_rx, pumps, OUTPUT_GRACE);
        let _ = out.json(Kind::Exit, &exit);
    }

    fn exec_tty(&self, spec: &ExecSpec, launch: &Launch, reader: UnixStream, out: &Out) {
        let (pty, pts) = match pty_process::blocking::open() {
            Ok(p) => p,
            Err(e) => {
                out.error(format!("allocate a terminal: {e}"));
                return;
            }
        };
        if spec.rows > 0 && spec.cols > 0 {
            let _ = pty.resize(pty_process::Size::new(spec.rows, spec.cols));
        }
        let child = match launch.pty().spawn(pts) {
            Ok(c) => c,
            Err(e) => {
                Self::not_started(out, &spec.argv[0], &io::Error::other(e.to_string()));
                return;
            }
        };
        let pid = child.id() as i32;
        let _ = out.json(Kind::Started, &Started { pid });
        let pty = Arc::new(pty);
        let (done_tx, done_rx) = mpsc::channel();
        {
            let (o, p) = (out.clone(), Arc::clone(&pty));
            thread::spawn(move || pump(&*p, Kind::Stdout, o, done_tx));
        }
        let exit_rx = self.reaper.watch(child);
        let finished = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&finished);
        let (w, rs) = (Arc::clone(&pty), Arc::clone(&pty));
        thread::spawn(move || {
            Self::control_loop(
                reader,
                pid,
                Some(Box::new(PtyWriter(w))),
                move |r| {
                    if r.rows > 0 && r.cols > 0 {
                        let _ = rs.resize(pty_process::Size::new(r.rows, r.cols));
                    }
                },
                f,
            );
        });
        let exit = exit_rx.recv().unwrap_or(Exit {
            code: -1,
            signal: None,
        });
        finished.store(true, Ordering::SeqCst);
        wait_n(&done_rx, 1, OUTPUT_GRACE);
        let _ = out.json(Kind::Exit, &exit);
    }

    fn file(&self, r: FileRequest, reader: UnixStream, out: &Out) {
        let ident = match self.identity(&r.user) {
            Ok(i) => i,
            Err(e) => {
                out.error(e);
                return;
            }
        };
        let path = self.resolve_path(&r.path);
        let streams = matches!(r.action, FileAction::Read | FileAction::TarOut);
        let takes_body = matches!(r.action, FileAction::Write | FileAction::TarIn);
        match &self.helper {
            HelperMode::InProcess => {
                let mut input = FrameReader {
                    conn: reader,
                    buf: Vec::new(),
                    pos: 0,
                    eof: !takes_body,
                };
                let mut output = FrameWriter(out.clone());
                match fileops::run(r.action, &path, r.mode, &mut input, &mut output) {
                    Ok(v) => {
                        let _ = out.json(Kind::Result, &v.unwrap_or_else(|| serde_json::json!({})));
                    }
                    Err(e) => out.error(e),
                }
            }
            HelperMode::SelfExec(exe) => {
                let mut cmd = Command::new(exe);
                cmd.arg("__file")
                    .args(crate::helper::identity_args(&ident))
                    .args([
                        "--action",
                        action_name(r.action),
                        "--mode",
                        &r.mode.to_string(),
                        "--",
                    ])
                    .arg(&path)
                    .env_clear()
                    .env("PATH", DEFAULT_PATH)
                    .stdin(if takes_body {
                        Stdio::piped()
                    } else {
                        Stdio::null()
                    })
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .process_group(0);
                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        out.error(format!("file helper: {e}"));
                        return;
                    }
                };
                let pid = child.id() as i32;
                let finished = Arc::new(AtomicBool::new(false));
                if let Some(mut w) = child.stdin.take() {
                    let f = Arc::clone(&finished);
                    thread::spawn(move || {
                        let mut input = FrameReader {
                            conn: reader,
                            buf: Vec::new(),
                            pos: 0,
                            eof: false,
                        };
                        if io::copy(&mut input, &mut w).is_err() && !f.load(Ordering::SeqCst) {
                            kill_group(pid, libc_sigkill());
                        }
                    });
                } else {
                    // Still notice the host going away.
                    let f = Arc::clone(&finished);
                    thread::spawn(move || Self::control_loop(reader, pid, None, |_| {}, f));
                }
                let mut result = Vec::new();
                let errbuf = Arc::new(Mutex::new(Vec::new()));
                let err_t = child.stderr.take().map(|mut e| {
                    let b = Arc::clone(&errbuf);
                    thread::spawn(move || {
                        let mut v = Vec::new();
                        let _ = e.read_to_end(&mut v);
                        *lock(&b) = v;
                    })
                });
                if let Some(mut o) = child.stdout.take() {
                    if streams {
                        let mut w = FrameWriter(out.clone());
                        let _ = io::copy(&mut o, &mut w);
                    } else {
                        let _ = o.read_to_end(&mut result);
                    }
                }
                if let Some(t) = err_t {
                    let _ = t.join();
                }
                let exit = self.reaper.watch(child).recv().unwrap_or(Exit {
                    code: -1,
                    signal: None,
                });
                finished.store(true, Ordering::SeqCst);
                if exit.code != 0 {
                    let msg = String::from_utf8_lossy(&lock(&errbuf)).trim().to_owned();
                    out.error(if msg.is_empty() {
                        format!(
                            "file {} {}: {exit:?}",
                            action_name(r.action),
                            path.display()
                        )
                    } else {
                        msg
                    });
                    return;
                }
                let value = if streams || result.is_empty() {
                    serde_json::json!({})
                } else {
                    match serde_json::from_slice(&result) {
                        Ok(v) => v,
                        Err(e) => {
                            out.error(format!("file helper output: {e}"));
                            return;
                        }
                    }
                };
                let _ = out.json(Kind::Result, &value);
            }
        }
    }
}

/// `SIGKILL`.
fn libc_sigkill() -> i32 {
    NixSignal::SIGKILL as i32
}

struct PtyWriter(Arc<pty_process::blocking::Pty>);

impl Write for PtyWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        (&*self.0).write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// The helper's spelling of a file action.
pub fn action_name(a: FileAction) -> &'static str {
    match a {
        FileAction::Write => "write",
        FileAction::Read => "read",
        FileAction::Mkdir => "mkdir",
        FileAction::Stat => "stat",
        FileAction::List => "list",
        FileAction::TarIn => "tar-in",
        FileAction::TarOut => "tar-out",
    }
}

/// Parses [`action_name`].
pub fn parse_action(s: &str) -> Option<FileAction> {
    Some(match s {
        "write" => FileAction::Write,
        "read" => FileAction::Read,
        "mkdir" => FileAction::Mkdir,
        "stat" => FileAction::Stat,
        "list" => FileAction::List,
        "tar-in" => FileAction::TarIn,
        "tar-out" => FileAction::TarOut,
        _ => return None,
    })
}

/// Forwards every TCP connection accepted on `listener` (the guest's proxy
/// address) to a fresh stream from `connect` (the host's egress port).
pub fn forward_egress<F>(listener: TcpListener, connect: F)
where
    F: Fn() -> io::Result<UnixStream> + Send + Sync + 'static,
{
    let connect = Arc::new(connect);
    for conn in listener.incoming() {
        let Ok(down) = conn else { continue };
        let connect = Arc::clone(&connect);
        thread::spawn(move || {
            let Ok(up) = connect() else {
                let _ = down.shutdown(Shutdown::Both);
                return;
            };
            splice(down, up);
        });
    }
}

/// Copies both directions until each side finishes.
fn splice(a: std::net::TcpStream, b: UnixStream) {
    let (Ok(mut a2), Ok(mut b2)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    let t = thread::spawn(move || {
        let mut a = a;
        let mut b = b;
        let _ = io::copy(&mut a, &mut b);
        let _ = b.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut b2, &mut a2);
    let _ = a2.shutdown(Shutdown::Write);
    let _ = t.join();
}
