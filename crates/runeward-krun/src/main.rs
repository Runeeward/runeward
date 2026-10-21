//! `runeward-krun CONFIG.json`: boots one Rune Box microVM with libkrun.
//!
//! The backend writes a [`KrunConfig`] and runs this helper; libkrun's
//! `krun_start_enter` turns the process into the VMM and only returns on
//! failure, so the VM's lifetime is this process's lifetime.
//!
//! libkrun is loaded at run time (`dlopen`), so building Rune Box needs no
//! libkrun headers or libraries; a host without libkrun gets a clear error.
//! The VM is configured for the Rune Box guest, never libkrun's defaults:
//!
//! - no implicit init: the guest agent is served as `/init.krun` from host
//!   memory on an otherwise empty root (`krun_set_root_disk_remount` plus
//!   `krun_fs_add_overlay_file`), so no host directory is shared;
//! - the image disk is attached read-only, the workspace disk read-write;
//! - the vsock device has **no TSI** (`krun_disable_implicit_vsock`, then
//!   `krun_add_vsock(ctx, 0)`): guest sockets are not proxied to the host
//!   network, and there is no network device, so the only ways out are the
//!   two vsock ports mapped to the host's agent and egress sockets.

#![cfg_attr(not(unix), allow(unused))]

use std::process::ExitCode;

use runeward_vmagent::proto::KrunConfig;

#[cfg(unix)]
#[allow(unsafe_code)]
mod krun {
    //! The libkrun C API, resolved with `dlsym`.

    use std::ffi::{CStr, CString, c_char, c_void};

    use runeward_vmagent::proto::KrunConfig;

    /// `KRUN_FEATURE_BLK`.
    const FEATURE_BLK: u64 = 1;

    /// The virtiofs tag of the root filesystem.
    const ROOT_TAG: &str = "/dev/root";

    struct Lib(*mut c_void);

    fn cstr(s: &str) -> Result<CString, String> {
        CString::new(s).map_err(|_| format!("{s:?} contains a NUL byte"))
    }

    fn dl_error() -> String {
        // SAFETY: dlerror returns NULL or a NUL-terminated string owned by
        // the loader, valid until the next dl* call on this thread.
        let p = unsafe { libc::dlerror() };
        if p.is_null() {
            "unknown error".into()
        } else {
            // SAFETY: non-null, NUL-terminated (see above).
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    }

    impl Lib {
        fn open(name: &str) -> Result<Self, String> {
            let c = cstr(name)?;
            // SAFETY: `c` is a valid C string; the handle is never closed,
            // since libkrun takes over the process.
            let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if h.is_null() {
                return Err(format!("load {name}: {}", dl_error()));
            }
            Ok(Self(h))
        }

        fn sym(&self, name: &str) -> Result<*mut c_void, String> {
            let c = cstr(name)?;
            // SAFETY: valid handle from dlopen and a valid C string.
            let p = unsafe { libc::dlsym(self.0, c.as_ptr()) };
            if p.is_null() {
                Err(format!(
                    "libkrun has no {name} (libkrun 1.19 or later is required): {}",
                    dl_error()
                ))
            } else {
                Ok(p)
            }
        }
    }

    /// Resolves `$name` from `$lib` as the C function type `$ty`.
    macro_rules! func {
        ($lib:expr, $name:literal, $ty:ty) => {{
            let p = $lib.sym($name)?;
            // SAFETY: the symbol is the libkrun 1.x C function of this
            // name, whose prototype (include/libkrun.h) is `$ty`.
            unsafe { std::mem::transmute::<*mut c_void, $ty>(p) }
        }};
    }

    fn check(what: &str, rc: i32) -> Result<(), String> {
        if rc < 0 {
            Err(format!(
                "{what}: {}",
                std::io::Error::from_raw_os_error(-rc)
            ))
        } else {
            Ok(())
        }
    }

    /// Configures the VM and enters it; returns only on failure.
    pub fn run(cfg: &KrunConfig) -> Result<(), String> {
        let lib = Lib::open(&cfg.library)?;
        let set_log_level = func!(lib, "krun_set_log_level", extern "C" fn(u32) -> i32);
        let has_feature = func!(lib, "krun_has_feature", extern "C" fn(u64) -> i32);
        let create_ctx = func!(lib, "krun_create_ctx", extern "C" fn() -> i32);
        let set_vm_config = func!(
            lib,
            "krun_set_vm_config",
            extern "C" fn(u32, u8, u32) -> i32
        );
        let disable_implicit_init =
            func!(lib, "krun_disable_implicit_init", extern "C" fn(u32) -> i32);
        let disable_implicit_vsock = func!(
            lib,
            "krun_disable_implicit_vsock",
            extern "C" fn(u32) -> i32
        );
        let add_vsock = func!(lib, "krun_add_vsock", extern "C" fn(u32, u32) -> i32);
        let add_disk = func!(
            lib,
            "krun_add_disk",
            extern "C" fn(u32, *const c_char, *const c_char, bool) -> i32
        );
        let set_root_disk_remount = func!(
            lib,
            "krun_set_root_disk_remount",
            extern "C" fn(u32, *const c_char, *const c_char, *const c_char) -> i32
        );
        let add_overlay_file = func!(
            lib,
            "krun_fs_add_overlay_file",
            extern "C" fn(u32, *const c_char, *const c_char, *const u8, usize, u32, bool) -> i32
        );
        let add_vsock_port2 = func!(
            lib,
            "krun_add_vsock_port2",
            extern "C" fn(u32, u32, *const c_char, bool) -> i32
        );
        let set_env = func!(
            lib,
            "krun_set_env",
            extern "C" fn(u32, *const *const c_char) -> i32
        );
        let set_console_output = func!(
            lib,
            "krun_set_console_output",
            extern "C" fn(u32, *const c_char) -> i32
        );
        let start_enter = func!(lib, "krun_start_enter", extern "C" fn(u32) -> i32);

        set_log_level(1);
        if has_feature(FEATURE_BLK) != 1 {
            return Err(
                "this libkrun was built without block device support (build it with BLK=1)".into(),
            );
        }
        let agent = std::fs::read(&cfg.agent)
            .map_err(|e| format!("read the guest agent {}: {e}", cfg.agent))?;
        // libkrun keeps a pointer to the data for the VM's lifetime.
        let agent: &'static [u8] = Box::leak(agent.into_boxed_slice());

        let ctx = create_ctx();
        check("krun_create_ctx", ctx)?;
        let ctx = ctx as u32;
        check(
            "krun_set_vm_config",
            set_vm_config(ctx, cfg.vcpus.max(1), cfg.ram_mib.max(128)),
        )?;
        check("krun_disable_implicit_init", disable_implicit_init(ctx))?;
        check("krun_disable_implicit_vsock", disable_implicit_vsock(ctx))?;
        check("krun_add_vsock (no TSI)", add_vsock(ctx, 0))?;
        let (root_id, rootfs) = (cstr("root")?, cstr(&cfg.rootfs)?);
        check(
            "krun_add_disk (image)",
            add_disk(ctx, root_id.as_ptr(), rootfs.as_ptr(), true),
        )?;
        if !cfg.workspace.is_empty() {
            let (ws_id, ws) = (cstr("workspace")?, cstr(&cfg.workspace)?);
            check(
                "krun_add_disk (workspace)",
                add_disk(ctx, ws_id.as_ptr(), ws.as_ptr(), false),
            )?;
        }
        let (dev, fstype, opts) = (cstr("/dev/vda")?, cstr("ext4")?, cstr("ro")?);
        check(
            "krun_set_root_disk_remount",
            set_root_disk_remount(ctx, dev.as_ptr(), fstype.as_ptr(), opts.as_ptr()),
        )?;
        let (tag, init) = (cstr(ROOT_TAG)?, cstr("init.krun")?);
        check(
            "krun_fs_add_overlay_file (agent)",
            add_overlay_file(
                ctx,
                tag.as_ptr(),
                init.as_ptr(),
                agent.as_ptr(),
                agent.len(),
                0o100_755,
                false,
            ),
        )?;
        let agent_sock = cstr(&cfg.agent_socket)?;
        check(
            "krun_add_vsock_port2 (agent)",
            add_vsock_port2(
                ctx,
                runeward_vmagent::proto::AGENT_PORT,
                agent_sock.as_ptr(),
                true,
            ),
        )?;
        if !cfg.egress_socket.is_empty() {
            let egress = cstr(&cfg.egress_socket)?;
            check(
                "krun_add_vsock_port2 (egress)",
                add_vsock_port2(
                    ctx,
                    runeward_vmagent::proto::EGRESS_PORT,
                    egress.as_ptr(),
                    false,
                ),
            )?;
        }
        let env: Vec<CString> = cfg.env.iter().map(|e| cstr(e)).collect::<Result<_, _>>()?;
        let mut envp: Vec<*const c_char> = env.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());
        check("krun_set_env", set_env(ctx, envp.as_ptr()))?;
        if !cfg.console.is_empty() {
            let console = cstr(&cfg.console)?;
            check(
                "krun_set_console_output",
                set_console_output(ctx, console.as_ptr()),
            )?;
        }
        check("krun_start_enter", start_enter(ctx))
    }
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: runeward-krun CONFIG.json");
        return ExitCode::from(2);
    };
    if path == "--version" {
        println!("runeward-krun {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let cfg: KrunConfig = match std::fs::read(&path)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runeward-krun: config {path}: {e}");
            return ExitCode::from(2);
        }
    };
    #[cfg(unix)]
    {
        if let Err(e) = krun::run(&cfg) {
            eprintln!("runeward-krun: {e}");
        }
        ExitCode::from(1)
    }
    #[cfg(not(unix))]
    {
        let _ = cfg;
        eprintln!("runeward-krun: libkrun needs Linux (KVM) or macOS (Hypervisor.framework)");
        ExitCode::from(1)
    }
}
