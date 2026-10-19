# Isolation tiers and runtimes

Every sandbox reports the isolation boundary it actually runs behind. A
Charter can require a floor, and a sandbox that falls short is refused
before anything runs in it.

```toml
[host]
type          = "container"   # or "k8s"
runtime_class = "io.containerd.kata-qemu.v2"  # the OCI runtime (Docker/Podman --runtime, k8s RuntimeClass)

[isolation]
minimum = "vm"                # process < container < kernel < vm
```

## Tiers

| Tier        | Boundary                                                        |
|-------------|-----------------------------------------------------------------|
| `process`   | A host process with in-process confinement only.                |
| `container` | Namespaces and cgroups on the host kernel (runc, crun).         |
| `kernel`    | A kernel that is not the host's: gVisor's user-space kernel, or a Kata guest kernel not confirmed as hardware-virtualised. |
| `vm`        | A hardware-virtualised guest: a libkrun or Firecracker microVM, or Kata on QEMU / Cloud Hypervisor when the evidence confirms it. |

## Runtimes

| `runtime_class`          | What it is                                   | Name claims | At most |
|--------------------------|----------------------------------------------|-------------|---------|
| empty, `runc`, `crun`    | Engine default, shared kernel                | container   | container |
| `runsc` (`gvisor`)       | gVisor                                       | kernel      | kernel  |
| `kata`, `kata-qemu`, `kata-clh`, `io.containerd.kata[-<h>].v2` | Kata Containers, QEMU or Cloud Hypervisor | kernel | vm |
| `kata-fc` (Kubernetes only) | Kata Containers with Firecracker          | vm          | vm      |
| `krun`                   | crun built with libkrun (not yet verified on a real host) | vm | vm |

`runtime_class` is passed as `docker run --runtime <name>` /
`podman run --runtime <name>`, or set as the Pod's `runtimeClassName` on
Kubernetes (the RuntimeClass's handler is what gets classified). An OCI
runtime written in `host.runtime` is used when `runtime_class` is empty
(`host.runtime` otherwise stays the `docker`/`podman` engine hint). An
unregistered runtime fails the create; Rune Box never falls back to the
default runtime.

## Evidence, not names

A runtime name is only a claim: a `krun` entry in `daemon.json` can point
at runc. Right after a sandbox starts, the backend runs a one-line POSIX
probe inside it (`/bin/sh` and `cat`) and compares the result with the
engine host's kernel (`docker info` / `podman info`, or the Kubernetes
node's `kernelVersion`):

- gVisor's signatures (`/proc/version`, `dmesg`, `/proc/cmdline`) → `kernel`;
- a guest kernel release different from the host's **and** a hypervisor
  marker (the x86 `hypervisor` CPU flag, a hypervisor DMI vendor,
  `/sys/hypervisor/type`, a `linux,dummy-virt` device tree on arm64,
  virtio-mmio devices on the kernel command line) → `vm`;
- a different kernel without a hypervisor marker → `kernel`;
- the host's own kernel, or anything unconfirmed (no shell in the image,
  probe failed, node kernel unreadable) → `container`.

Observed on a KVM host (Debian 13, Kata 4.2.0): kata-qemu and kata-clh
guests report kernel `6.18.35` against host `6.12.100+deb13-cloud-amd64`, with
the `hypervisor` CPU flag and an empty DMI vendor; runc guests report the
host's kernel.

The name does not identify the hypervisor either: Kata 4's runtime-rs shim
loads the first `runtime-rs/configuration.toml` it finds (under
`/etc/kata-containers`, `/usr/share/defaults/kata-containers`,
`/opt/kata/share/defaults/kata-containers`) whatever the shim is called, so a
runtime named `kata-clh` or `kata-fc` can silently run QEMU. For a `vm`
sandbox on a Docker/Podman engine running on the same machine, the backend
finds the `qemu-system-*`, `cloud-hypervisor` or `firecracker` process whose
command line carries the container id and records it (`hypervisor`, signal
`host:hypervisor=qemu`, plus `host:hypervisor-mismatch=...` and a warning
when it contradicts the name). When host processes are not visible (remote
engine, Kubernetes) it reports `vm` with hypervisor `unknown`.

The result is capped at the runtime's ceiling (the "At most" column), so a
sandbox's own output can never lift runc or gVisor to `vm`. When the name
claims more than the evidence shows, the weaker tier is reported and an
`ISOLATION DOWNGRADE` warning is logged.

The evidence is stored on the sandbox (`IsolationEvidence`: `runtime`,
`guest_kernel`, `host_kernel`, `signals`, `hypervisor`) and written to the
ledger on the `sandbox create` event (and on a refused create) as
`isolation_runtime`, `isolation_guest_kernel`, `isolation_host_kernel`,
`isolation_signals` and `isolation_hypervisor`, for example:

```
isolation_signals = probe:ok,kernel:separate,hypervisor:cpu-flag,claim:kernel,host:hypervisor=qemu,verdict:vm
```

The probe detects misconfiguration, not a hostile image: it trusts the
image's `/bin/sh`. `RUNEWARD_ISOLATION_PROBE=off` skips it and trusts the
runtime name; the evidence then records `probe:disabled`.

On Kubernetes the server and controller need `get` on `nodes` and
`runtimeclasses` (granted by the Helm chart and install manifests);
without them the node kernel is unknown and VM runtimes report `container`.

## Installing a runtime

`runeward runtime install <gvisor|kata|kata-fc|krun> [--engine docker|podman|k8s] [--hypervisor qemu|clh] [--apply]`
prints host checks and the exact steps; nothing changes without `--apply`.
Without root it verifies downloads into a staging directory and prints the
`sudo` commands to finish. A failing check (for example no `/dev/kvm`)
refuses `--apply`.

Host checks for VM runtimes: Linux host, `/dev/kvm` present and openable,
nested virtualisation when the host is itself a VM, and not a desktop engine
(Docker Desktop, OrbStack and Podman machine run containers inside a VM
without nested virtualisation, so `kata*` and `krun` cannot run there;
gVisor can).

### gVisor (`runsc`)

Docker/Podman: downloads `runsc` and `containerd-shim-runsc-v1` from the
gVisor release bucket, verified against a `--sha256` pin or the bucket's
`.sha512` sidecar (fail closed), installs them into `/usr/local/bin`, and
for Docker merges into `/etc/docker/daemon.json`:

```json
{ "runtimes": { "runsc": { "path": "/usr/local/bin/runsc" } } }
```

Restart Docker (`systemctl restart docker`). Podman finds `runsc` in
`/usr/local/bin` by name. No KVM needed.

Kubernetes: install `runsc` and its shim on the nodes, register the
`runsc` handler in containerd, and apply:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

### Kata Containers (`kata`, `kata-qemu`, `kata-clh`)

Install Kata from its static release (`/opt/kata`) or your distribution (not
automated). Docker needs no `daemon.json` change: it runs containerd shims by
runtime type. Put the shim on dockerd's PATH under the name containerd looks
up, and pass the runtime type:

```sh
ln -sf /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-qemu-v2
docker run --runtime io.containerd.kata-qemu.v2 ...   # host.runtime_class = "io.containerd.kata-qemu.v2"
```

`runeward runtime install kata [--hypervisor qemu|clh]` plans exactly that.
Because runtime-rs picks the hypervisor from `runtime-rs/configuration.toml`
(see above), also point `/etc/kata-containers/runtime-rs/configuration.toml`
at the configuration for the hypervisor you want; `KATA_CONF_FILE` is only
honoured when it resolves to one of the same three paths. The evidence shows
which hypervisor actually ran.

Kubernetes: install with kata-deploy and use a RuntimeClass whose handler is
`kata` (or `kata-qemu` / `kata-clh`). These report `vm` when the evidence
shows a hardware-virtualised guest.

### Kata with Firecracker (`kata-fc`)

Not available on Docker or Podman; the Charter lint and the backend refuse
it there. Firecracker has no shared filesystem (virtio-fs/9p), so Kata fails
with "share fs is unavailable", and it has no device hot-plug, so networking
fails with "add net device: After 500 attempts". Firecracker itself boots
fine on a KVM host; what it needs is a block-device root filesystem.
Supported routes:

1. **Kubernetes with containerd's devmapper snapshotter** on the nodes and a
   `kata-fc` RuntimeClass (`host.type = "k8s"`). Kata 4.2.0 ships an invalid
   runtime-rs `configuration-rs-fc.toml`: `dial_timeout_ms = 45000` without
   `reconnect_timeout_ms` fails validation; set `dial_timeout_ms = 10` and
   `reconnect_timeout_ms = 45000`. RuntimeClass (kata-deploy's handler, pod
   overhead and node label):

   ```json
   { "apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
     "metadata": { "name": "kata-fc" }, "handler": "kata-fc",
     "overhead": { "podFixed": { "cpu": "250m", "memory": "130Mi" } },
     "scheduling": { "nodeSelector": { "katacontainers.io/kata-runtime": "true" } } }
   ```

2. **A native Firecracker driver** (`host.type = "microvm"`, below): not
   implemented yet.

### libkrun (`krun`)

Install crun built with libkrun (`dnf install crun-krun` on Fedora/CentOS
Stream, or build libkrunfw, libkrun and `crun --with-libkrun`), which
provides `/usr/bin/krun`. Requires `/dev/kvm`. libkrun is not packaged
for every distribution (Debian 13 has none), and `krun` has not been
verified on a real host by Rune Box yet; its tier comes from the evidence
like any other runtime.

- Docker: `{ "runtimes": { "krun": { "path": "/usr/bin/krun" } } }`
- Podman: knows `krun` by name; nothing to register.
- Kubernetes: register the handler on each node (CRI-O
  `[crio.runtime.runtimes.krun] runtime_path = "/usr/bin/krun"`, or a
  containerd `io.containerd.runc.v2` runtime with
  `BinaryName = "/usr/bin/krun"`) and apply a RuntimeClass with
  `handler: krun`.

## Verifying on a KVM host

The opt-in test creates a sandbox under a runtime and asserts that the
evidence proves `vm`:

```sh
RUNEWARD_TEST_VM_RUNTIME=io.containerd.kata-qemu.v2 \
RUNEWARD_TEST_VM_HYPERVISOR=qemu \
cargo test -p runeward-backend --test vm_runtime -- --nocapture
```

`RUNEWARD_TEST_VM_ENGINE=docker|podman|k8s` picks the engine,
`RUNEWARD_TEST_VM_IMAGE` overrides `alpine`, and `RUNEWARD_TEST_DOCKER=1`
also checks that the default runtime reports `container`.

## A native microVM driver

microVMs are delivered through OCI runtimes so the request broker,
in-sandbox supervisor, file and exec paths stay the same. `host.type =
"microvm"` is reserved for a future driver that boots libkrun or Firecracker
directly; it is not implemented.
