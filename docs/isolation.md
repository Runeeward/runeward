# Isolation tiers and runtimes

Every sandbox reports the isolation boundary it actually runs behind. A
Charter can require a floor, and a sandbox that falls short is refused
before anything runs in it.

```toml
[host]
type          = "container"   # or "k8s", or "microvm" (below)
runtime_class = "io.containerd.kata-qemu.v2"  # the OCI runtime (Docker/Podman --runtime, k8s RuntimeClass)

[isolation]
minimum = "vm"                # process < container < kernel < vm
```

## Tiers

| Tier        | Boundary                                                        |
|-------------|-----------------------------------------------------------------|
| `process`   | A host process with in-process confinement only.                |
| `container` | Namespaces and cgroups on the host kernel (runc, crun).         |
| `kernel`    | A kernel that is not the host's: gVisor's user-space kernel, or a VM runtime's guest kernel whose hardware virtualisation the evidence could not confirm. |
| `vm`        | A hardware-virtualised guest: Kata on QEMU, Cloud Hypervisor or Firecracker, or a native Firecracker or libkrun microVM. |

## Runtimes

| `runtime_class`          | What it is                                   | Name claims | At most |
|--------------------------|----------------------------------------------|-------------|---------|
| empty, `runc`, `crun`    | Engine default, shared kernel                | container   | container |
| `runsc` (`gvisor`)       | gVisor                                       | kernel      | kernel  |
| `kata`, `kata-qemu`, `kata-clh`, `io.containerd.kata[-<h>].v2` | Kata Containers, QEMU or Cloud Hypervisor | vm | vm |
| `kata-fc` (Kubernetes only) | Kata Containers with Firecracker; the workspace persists only on a direct-volume StorageClass | vm | vm |
| `krun`                   | crun built with libkrun: **refused** (no exec into a running guest); use the native libkrun driver | vm | refused |

With `host.type = "microvm"` there is no OCI runtime: `host.runtime` names
the monitor Rune Box boots itself, `firecracker` or `libkrun` (see
[Native microVMs](#native-microvms-hosttype-microvm)). Both claim `vm` and
are confirmed from guest evidence like every other runtime.

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
isolation_signals = probe:ok,kernel:separate,hypervisor:cpu-flag,claim:vm,host:hypervisor=qemu,verdict:vm
```

Every Kata runtime boots a hardware VM, so its name claims `vm`, like
`kata-fc` and `krun`; the claim is only what an unprobed sandbox reports
(`RUNEWARD_ISOLATION_PROBE=off`) and what a downgrade is measured against.
The verdict always comes from the evidence.

The probe detects misconfiguration, not a hostile image: it trusts the
image's `/bin/sh`. `RUNEWARD_ISOLATION_PROBE=off` skips it and trusts the
runtime name; the evidence then records `probe:disabled`.

On Kubernetes the server and controller need `get` on `nodes` and
`runtimeclasses` (granted by the Helm chart and install manifests);
without them the node kernel is unknown and VM runtimes report `container`.

## Sizing VM sandboxes

A VM runtime turns the sandbox's container limits into a guest. Kata sizes
the guest as its configured `default_memory` and `default_vcpus` **plus**
the container's memory and CPU limits, so the default limits
(`RUNEWARD_SANDBOX_MEMORY=4g`, `RUNEWARD_SANDBOX_CPUS=2`) become a guest of
6144 MiB and 3 vCPUs. When that does not fit on the engine host the
hypervisor never starts, and the engine only reports a shim timeout.

Before it asks Docker or Podman for a sandbox under a VM runtime (Kata,
krun, Firecracker), the backend computes

```
guest memory = sandbox memory limit + RUNEWARD_VM_OVERHEAD_MEMORY  (default 2048m)
guest vCPUs  = ceil(sandbox CPU limit) + ceil(RUNEWARD_VM_OVERHEAD_CPUS)  (default 1)
```

where the sandbox limits are the Charter's `[rationing] memory` / `cpus`,
else `RUNEWARD_SANDBOX_MEMORY` / `RUNEWARD_SANDBOX_CPUS`. It compares them
with the engine host's total memory and CPUs (`docker info` `MemTotal` /
`NCPU`, `podman info` `Host.MemTotal` / `Host.CPUs`, read once when the
backend starts) and refuses the sandbox when either is larger, naming the
sizes and what to lower. The overhead defaults are Kata's shipped
`default_memory = 2048` and `default_vcpus = 1`; set the two
`RUNEWARD_VM_OVERHEAD_*` variables to match your runtime's configuration
(`0`/`off` for none, for example for a runtime that sizes the guest from
the limit alone). When the engine does not report its capacity, nothing is
refused. The check passing does not guarantee a boot: the host also needs
memory for itself and other sandboxes. Kubernetes accounts for VM overhead
through the RuntimeClass's `overhead.podFixed` and the scheduler instead.

**Kata with Firecracker sizes the guest differently.** Firecracker cannot
hot-plug memory or CPUs, so Kata's Firecracker configuration sets
`static_sandbox_resource_mgmt = true`: the guest is sized once, at boot,
from the Pod's limits, and `default_memory` / `default_vcpus` are replaced
rather than added to:

```
guest memory = overhead_memory + the Pod's container memory limits
guest vCPUs  = overhead_vcpus  + the Pod's container CPU limits
```

On the test host a sandbox with a 512 MiB limit ran in a 512 MiB guest. The
guest kernel and Kata's agent run in that memory too, so the sandbox has
less than its limit. Set `overhead_memory` (for example `256`) and
`overhead_vcpus` in Kata's Firecracker configuration, and the RuntimeClass's
`overhead.podFixed` to match so the scheduler counts them. Rune Box gives
the egress sidecar its own limits (500m CPU, 256 MiB), so a sandbox that
needs it gets a guest with room for the proxy.

When a VM sandbox still fails to start with a known VM start failure
(`timed out waiting for QMP ready`, `start vm`, `failed to create shim
task`), the error names the likely causes: the guest size against the host
memory, the runtime not being able to use `/dev/kvm` (permissions, or no
nested virtualisation), or a broken hypervisor configuration
(`/etc/kata-containers/runtime-rs/configuration.toml`). A failed create
never leaves the container, the egress sidecar or the workspace volume
behind (on Kubernetes: the Pod, ConfigMap, Secret, NetworkPolicy or PVC).

## The in-sandbox supervisor and the runtime

`runeward-supervisor` (`[filesystem]`, `[process]`) confines the agent with
whatever kernel the sandbox sees: the host's under runc, the guest kernel
under Kata (any hypervisor), gVisor's own kernel under runsc. It probes
Landlock when it starts: `best-effort` uses the best ABI that kernel offers
and reports `unsupported` when it has none; `required` refuses below ABI 3,
and the create fails with the supervisor's reason (on Kubernetes the
sandbox container exits 77, and the backend reports it without waiting out
the start timeout). The report records the ABI and the seccomp filter that
were installed, so a guest kernel built without Landlock, or a user-space
kernel that does not implement it, shows up as evidence rather than as a
silent gap. The isolation probe runs after the supervisor has started and
does not need to predict any of this.

Docker/Podman and Kubernetes give the same guarantees; on Kubernetes the
binary comes from the egress image through an init container (see the
Firecracker drive budget below). On kind (runc, kernel 7.2, Landlock ABI 9)
the opt-in test `k8s_governance` showed governed execs as uid 1500 with
empty capability sets, Landlock refusing writes and reads outside the
Charter's paths, `ptrace` and `unshare -U` refused, and the report
(`landlock: enforced`) on the Citadel, with its own init container and
under strict egress. The Kata and gVisor paths have not been run against a
cluster yet.

## Tested hosts

On a KVM host (Debian 13 cloud VM, 2 vCPUs, 3.8 GiB RAM, host kernel
`6.12.100+deb13-cloud-amd64`, Docker 29, Kata 4.2.0 runtime-rs):

- `io.containerd.kata-qemu.v2` and `io.containerd.kata-clh.v2` both booted
  with evidence verdict `vm`, guest kernel `6.18.35`, and the host-side
  hypervisor process found (`host:hypervisor=qemu`,
  `host:hypervisor=cloud-hypervisor`).
- Kata 4.2.0 runtime-rs picks the hypervisor from the first existing
  `runtime-rs/configuration.toml` (`/etc/kata-containers` first), not from
  the shim name. With the shim named `kata-clh` and the configuration on
  QEMU, the evidence recorded `host:hypervisor-mismatch=cloud-hypervisor->qemu`.
- With the default limits the VM never started (6144 MiB guest on a
  3.8 GiB host; the engine reported `timed out waiting for QMP ready`);
  with `RUNEWARD_SANDBOX_MEMORY=512m RUNEWARD_SANDBOX_CPUS=1` it booted.
  The backend now refuses the first case up front.
- runc on the same host reports verdict `container`: the host is itself a
  VM, so the `hypervisor` CPU flag is present even for runc, but the guest
  kernel is the host's.
- The shipped Firecracker configuration needed `dial_timeout_ms = 10` and
  `reconnect_timeout_ms = 45000`; Firecracker needs a block-device root
  filesystem, so it is refused on Docker/Podman (below).

`kata-fc` on Kubernetes, same host (k3s 1.37 in a privileged container,
containerd 2.3 with the devmapper snapshotter on loop-file thin pools,
Kata 4.2.0 runtime-rs, Firecracker 1.12.1, guest memory 512 MiB):

- The sandbox booted with verdict `vm`, guest kernel `6.18.35`, guest root
  `/dev/vdc` (ext4 from devmapper); signals
  `probe:ok,kernel:separate,hypervisor:cpu-flag,hypervisor:cmdline=virtio_mmio,claim:vm,host:hypervisor=unknown,verdict:vm`.
  Exec, file operations and destroy (Pod and PVC removed) worked.
- `/workspace` inside the guest was a 96 MB **tmpfs**, not the workspace
  PVC: Firecracker cannot share a filesystem volume into the guest. Files
  written there never reached the PVC and were gone after sleep and wake.
  The probe now records `workspace:ephemeral=tmpfs`, and a Charter with
  `[workspace] persist = true` is refused on such a runtime (by the lint
  for `kata-fc` on Kubernetes, and by the backend at create and wake).
- Kata's stock `csi-kata-directvolume` (4.2.0) deletes the backing disk in
  NodeUnstageVolume, so the first sleep wiped the workspace and the wake
  formatted a new one. Its slot handling also left no drive for an egress
  sidecar next to a direct-volume workspace and the init container that
  then made it writable. Both led to the bundled driver below.
- With the bundled driver (`sandbox.directVolumeDriver.enabled=true`, Kata
  4.3.0 runtime-rs, Firecracker 1.17.0, k3s 1.37): verdict `vm`;
  `/workspace` was `/dev/vdd`, ext4, root `0:0 1777`, written by the image's
  user (uid 1000); the Pod had no init container and used three drives.
  Files survived three sleep/wake cycles (the backing disk kept its inode;
  each wake took about 5 s), and a driver restart while the workspace slept.
- `[network] default = "deny"` with a persistent workspace (four drives)
  started in about 8 s and the proxy allowed and denied hosts as written;
  with strict egress (five drives) bypassing the proxy failed too. Strict
  egress, a broker and a persistent workspace (six drives) were refused in
  25 ms with nothing created, and `runeward validate` reported it. In a
  plain Pod, the drives of exited init containers were never reused, so a
  sixth drive user fails under 4.3.0 as well.
- Destroy, of a running or a sleeping workspace, removed the Pod, PVC, PV,
  backing disk, Kata mount info and driver state.
- A RuntimeClass whose handler containerd does not know used to wait out
  the full 90 s start timeout; a repeated `FailedCreatePodSandBox` event now
  fails the create at once with the kubelet's message. A failed create left
  no objects behind either way.

`krun`, same host (a privileged Fedora 42 container: Podman 5.8.2, crun
1.27.1, libkrun 1.17.4, libkrunfw 5.3.0):

- The guest is a real VM: guest kernel `6.12.76` against the host's,
  `hypervisor` CPU flag, `virtio_mmio.device=` on the command line, root on
  virtio-fs; the VMM is the container process itself, so no separate
  hypervisor process shows on the host. A 512m limit gave a 516 MiB guest
  (no Kata-style overhead).
- `podman exec` into the running guest fails with `the handler does not
  support exec`. Rune Box runs every command, file operation and the
  isolation probe through exec, so the create was refused
  (`probe:failed=...`, verdict `container`); with the probe off the sandbox
  started but every command failed. `krun` is therefore refused (below).

Native microVMs (`host.type = "microvm"`), same host, as an unprivileged
user in the `kvm` group, no container engine involved: Firecracker 1.15.1
with the Firecracker CI kernel `6.1.155`, and libkrun 1.19.6 (built with
`BLK=1`) with libkrunfw 5.6.2. Both reported verdict `vm` with the monitor
confirmed on the host, ran exec, TTY, files and workspace export, had no
route around the egress proxy, kept the workspace disk across sleep and
wake, and left nothing behind on destroy. A supervised, read-only sandbox
from the `runeward-sandbox` image (about 110 s to pull and build its disk the
first time, 2 s afterwards) ran its execs as the image user under the
supervisor's seccomp filter. Details in
[Native microVMs](#native-microvms-hosttype-microvm).

## Installing a runtime

`runeward runtime install <gvisor|kata> [--engine docker|k8s] [--runtime-class NAME] [--version V] [--sha256 HEX] [--apply]`
prints the exact plan; nothing changes without `--apply`. Without root it
verifies downloads into a temporary directory and prints the `sudo` commands
to finish. It does not check the host for VM support; confirm the
requirements below yourself.

Host requirements for VM runtimes: Linux host, `/dev/kvm` present and openable,
nested virtualisation when the host is itself a VM, and not a desktop engine
(Docker Desktop, OrbStack and Podman machine run containers inside a VM
without nested virtualisation, so `kata*` cannot run there;
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

`runeward runtime install kata` takes the other route: it does not install
Kata, but with `--apply` it finds `containerd-shim-kata-v2` (or the older
`kata-runtime` binary) and registers it in `/etc/docker/daemon.json` as a
runtime named `kata`, so `runtime_class = "kata"` works. The names differ
because they name different things: `containerd-shim-kata-v2` and
`kata-runtime` are Kata binaries, `kata` is a Docker runtime name registered
in `daemon.json`, and `io.containerd.kata-qemu.v2` is a containerd runtime
handler (type) that containerd resolves to the shim
`containerd-shim-kata-qemu-v2`.

Either way, because runtime-rs picks the hypervisor from `runtime-rs/configuration.toml`
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

2. **The native Firecracker driver** (`host.type = "microvm"`,
   `host.runtime = "firecracker"`, see
   [Native microVMs](#native-microvms-hosttype-microvm)): no Kubernetes or
   Kata; the workspace is a per-sandbox disk image and persists.

**Workspaces.** Kata with Firecracker cannot share a filesystem volume
into the guest, so an ordinary workspace PVC appears inside it as a small
guest tmpfs: nothing written there reaches the volume, and a sleep, wake or
restart loses it. Without further setup use `kata-fc` for disposable
sandboxes; a Charter with `[workspace] persist = true` is refused.

To keep workspaces, give persistent workspaces a direct-assigned block
device. The simplest way is the Helm chart's build of Kata's
`csi-kata-directvolume` driver:

```sh
helm upgrade --install runeward deploy/helm/runeward \
  --set sandbox.directVolumeDriver.enabled=true \
  --set-json 'sandbox.directVolumeDriver.nodeSelector={"katacontainers.io/kata-runtime":"true"}'
```

It runs the driver as a DaemonSet on the Kata nodes, creates the
`runeward-kata-directvolume` StorageClass and points
`RUNEWARD_K8S_DIRECT_VOLUME_CLASS` at it. Persistent workspaces of runtimes
without a shared filesystem then use that class and the guest mounts a real
ext4 disk; disposable ones keep the guest tmpfs, which spares a drive slot.
The disks live in `/var/lib/runeward/direct-volumes` on the node they were
created on, so a woken workspace is scheduled back to that node.

The image (`runeward-csi-directvolume`, built from
`deploy/Dockerfile.csi-directvolume`) is Kata 4.3.0's driver with three
changes:

- **It keeps the disk until the volume is deleted.** Kata's driver deletes
  the backing disk in NodeUnstageVolume, which runs whenever the last Pod
  using the volume goes away. A sleep deletes the Pod, so the wake got a
  new, empty disk and the workspace was lost without an error. Ours deletes
  it in DeleteVolume, when the workspace is destroyed.
- **It hands a new filesystem over world-writable.** The disk is formatted
  on the node, root-owned, and Kata applies no `fsGroup` to direct volumes,
  so the sandbox user could not write to it. Ours makes a new filesystem's
  root `1777` (like `/tmp`, inside a VM only this sandbox uses); a
  workspace already in use is never changed.
- **It deletes a disk only after the node has unmounted it.** Destroying a
  workspace removes the Pod and the claim together, and Kata's driver
  deleted the disk while the node still had it mounted. Ours refuses until
  the node has unstaged the volume (the provisioner retries), and also
  removes a disk whose volume record is already gone.

To bring your own driver instead, set `sandbox.directVolumeStorageClass` (or
`RUNEWARD_K8S_DIRECT_VOLUME_CLASS`) to its StorageClass; it needs the first
two changes above.

**Firecracker has five drive slots per pod.** Every container root
filesystem (the pause container and init containers included) and every
block volume takes one, and Kata 4.2.0 and 4.3.0 do not reuse the slot of an
exited init container (4.3.0 resets it to its placeholder but never hands it
out again; see
[kata-containers#13565](https://github.com/kata-containers/kata-containers/issues/13565)).
Rune Box counts the drives a sandbox's Pod needs and refuses it before
creating anything when they exceed five; `runeward validate` flags the
one Charter shape that does:

| Pod | Drives |
| --- | --- |
| pause, sandbox, persistent workspace | 3 |
| + egress sidecar (`[network] default = "deny"` or a broker) | 4 |
| + strict egress init container | 5 |
| + broker trust-bundle init container (strict egress, broker and a persistent workspace) | 6: refused |

The in-sandbox supervisor (`[filesystem]` or `[process]`) is installed by
an init container from the egress image, which takes a drive, except under
strict egress, where the iptables init container installs it too and the
Pod needs no extra drive. Its emptyDirs are memory-backed and stay in the
guest. With the supervisor:

| Pod | Drives |
| --- | --- |
| pause, supervisor, sandbox (+ persistent workspace) | 3 (4) |
| + egress sidecar, cooperative `[network] default = "deny"` | 4 (5) |
| + strict egress (its init container installs the supervisor) | 4 (5) |
| broker, cooperative: pause, trust-bundle, supervisor, sandbox, egress | 5 (6: see below) |
| broker and strict egress | 5 (6: refused, as without the supervisor) |

The supervisor never costs a Charter that does not require it its
sandbox. A cooperative broker with a persistent workspace (five drives
without the supervisor) and a best-effort `[filesystem]` starts without
the supervisor: the agent runs unconfined, the control plane records the
supervisor as `absent` with that reason, and `runeward validate` warns.
Only a Charter that requires the supervisor (`[process]` or
`landlock = "required"`) is refused in that shape, and `runeward validate`
reports it as an error. Every other combination, including strict egress
with the supervisor and a persistent workspace, fits in five. Use
`kata-qemu` or `kata-clh` for the refused shapes.

Both limits are tracked in
[#79](https://github.com/Runeeward/runeward/issues/79).

### libkrun (`krun`): refused

crun's libkrun handler boots a real microVM but cannot execute a command in
a running guest (`podman exec` fails with "the handler does not support
exec"; Docker and Kubernetes reach the same handler). Rune Box needs exec
for every command, file operation and the isolation probe, so `krun` is
refused by the Charter lint, the Docker/Podman and Kubernetes backends (a
RuntimeClass whose handler is `krun`), and `runeward runtime install`.
Use `kata-qemu` or `kata-clh` for a VM boundary on Docker or Podman, or the
native libkrun driver (`host.type = "microvm"`, `host.runtime = "libkrun"`),
which drives libkrun directly and has exec.

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

## Native microVMs (`host.type = "microvm"`)

The `microvm` backend boots one microVM per sandbox itself: no container
engine, no Kata, no Kubernetes. Two monitors share one guest design:

| `host.runtime`   | Monitor | Guest kernel | Hosts |
|------------------|---------|--------------|-------|
| `firecracker`    | Firecracker (`firecracker --no-api --config-file`) | the operator's (`RUNEWARD_MICROVM_KERNEL`) | Linux with `/dev/kvm` |
| `libkrun` (`krun`) | libkrun, loaded by the `runeward-krun` helper | libkrunfw's bundled kernel | Linux with `/dev/kvm`; macOS on Apple silicon (see [macOS](#macos)) |

An empty `host.runtime` takes `RUNEWARD_MICROVM_VMM`, else Firecracker when
it is configured, else libkrun.

```toml
[host]
type    = "microvm"
runtime = "firecracker"          # or "libkrun"
image   = "curlimages/curl:8.11.1"

[network]
default = "deny"
[[network.rule]]
hostname = "example.com"

[workspace]
persist = true

[isolation]
minimum = "vm"
```

### How a sandbox is built

- **Image.** The Charter's image is pulled straight from its registry
  (anonymously, for `linux/<host arch>`; layers are verified against their
  digests), its layers are applied with OCI whiteouts into a staging
  directory (every write confined to it, so a hostile layer cannot write
  outside), and the tree becomes an ext4 disk. The real owners and modes
  (setuid bits, root-only files) are written into the disk with `debugfs`, so
  the build never needs root. The disk is cached by manifest digest under
  `RUNEWARD_MICROVM_DIR/images` and shared, **read-only**, by every VM of that
  image; a tag that cannot be resolved (registry unreachable) falls back to
  the disk it last resolved to. gzip and uncompressed layers are supported;
  zstd layers are refused.
- **Guest.** `runeward-vmagent`, a static binary, is the guest's PID 1:
  Firecracker boots it as the initramfs `/init`, libkrun serves it as
  `/init.krun` from host memory on an otherwise empty root (libkrun's own
  init is disabled), so the agent never sits on the image disk and any image
  boots unmodified. The agent mounts the image disk read-only under an
  overlay whose upper layer is guest memory, mounts `/proc`, `/sys`, `/dev`
  and the workspace disk inside it, and `chroot`s into it.
  `host.read_only = true` remounts that root read-only once the sandbox is
  staged, with a 512 MiB tmpfs `/tmp`; the supervisor state and broker CA
  directories stay writable, as container engines keep volumes there.
- **Protocol.** The host reaches the agent over vsock (Firecracker's Unix
  socket with `CONNECT <port>`; a libkrun port-to-socket mapping). One stream
  per operation: exec with streamed stdin/stdout/stderr, a TTY with resizes,
  signals and the exit status; file write/read/stat/list and workspace tar
  streams; the isolation probe; shutdown. Closing a stream kills what it
  started. Commands and file operations run in a helper process that drops to
  the sandbox user first, so a link planted in the workspace cannot redirect
  a write into a root-owned file.
- **Workspace.** A per-sandbox ext4 disk image (`RUNEWARD_MICROVM_DISK_SIZE`,
  default `8g`, sparse) at the workspace directory. A fresh disk takes the
  owner and mode of the image's directory there, or the sandbox user when the
  image has none.
- **Sleep and wake.** `stop` asks the agent to stop every process, flush and
  unmount the workspace and reboot (the monitor exits), then kills the monitor
  if it is still running after 15 s. The workspace disk and the sandbox id
  stay; guest memory (the overlay, `/tmp`, processes) is gone. `start` boots a
  new VM on the same disk with a fresh egress path. `kill` removes the VM
  directory: disk, sockets, logs.
- **Sizing.** The guest gets the sandbox's memory limit (at least 256 MiB)
  and its CPU limit rounded up to whole vCPUs; the operator defaults
  (`RUNEWARD_SANDBOX_MEMORY`, `RUNEWARD_SANDBOX_CPUS`) apply as on Docker.

### Egress: no network device

The guest has **no network device** (Firecracker gets no
`network-interfaces`; libkrun gets no virtio-net and its vsock is created
with TSI disabled, so guest sockets are not proxied onto the host network;
libkrunfw's kernel shows a `dummy0` device with nothing behind it). Its only
way out is vsock: the agent listens on `127.0.0.1:3128` inside the guest,
`HTTP_PROXY`/`HTTPS_PROXY` point there, and every connection is forwarded
over vsock to a per-sandbox Unix socket on the host, where the Charter's
egress proxy (with the request broker when the Charter has
`[[endpoint]]`s or `[[credential]]`s) decides exactly as on the container
backends. Firecracker delivers guest-initiated vsock connections only to
`<vsock socket>_<port>` in the VM's own directory, where the egress socket
is the only one; libkrun only to the ports it was given. Checked from inside
both guests: host vsock ports 22, 2375 and the agent's own port were reset
(Firecracker) or timed out (libkrun); only the egress port answered.

This is why deny-by-default cannot be bypassed from inside: there is no
route to bypass it with, whatever a root process in the guest does, and it
holds for `enforce = "strict"` and `"cooperative"` alike. The price is that
only proxy-aware traffic leaves at all: raw TCP, UDP and DNS lookups fail
even under an open policy (`runeward validate` warns about that), and the
in-cell IDE, which needs a sandbox address, is refused. Broker CAs are
installed in the guest trust store as on the other backends.

### Isolation evidence

The agent collects the same probe sections as the container backends'
shell probe, natively, so an image without a shell still reports evidence.
The verdict uses the same rules: `vm` needs a guest kernel different from
the host's **and** a hypervisor marker, and the backend additionally
records `host:hypervisor=<monitor>` only while the monitor process it
launched is still running. A sandbox whose probe fails reports `container`.

Observed on the KVM test host (Debian 13, kernel `6.12.100+deb13-cloud-amd64`,
2026-10-21):

| Monitor | Guest kernel | Signals |
|---------|--------------|---------|
| Firecracker 1.15.1 | `6.1.155+` (Firecracker CI kernel) | `kernel:separate`, `hypervisor:cpu-flag`, `hypervisor:cmdline=virtio_mmio`, `host:hypervisor=firecracker`, `verdict:vm` |
| libkrun 1.19.6 + libkrunfw 5.6.2 | `6.12.109` | `kernel:separate`, `hypervisor:cpu-flag`, `hypervisor:cmdline=virtio_mmio`, `host:hypervisor=libkrun`, `verdict:vm` |

### Settings refused or changed

| Setting | On `microvm` |
|---------|--------------|
| `host.seccomp`, `host.apparmor` | Refused: container-engine profiles. The monitor runs under its own seccomp filters (Firecracker's built-in ones); use `[process]` for in-guest seccomp. |
| `[ide] enabled` | Refused: no sandbox network address. |
| `[filesystem] landlock = "required"` | Works when the guest kernel has Landlock. libkrunfw is built without it, and the Firecracker CI 6.1 kernel too; `runeward validate` warns for libkrun. |
| `host.user`, `host.command`, `[process]`, broker, `[[file]]`, `copy_from`, snapshots | As on Docker. |

### Setting up a host

1. The static guest agent:
   `cargo build --release --target x86_64-unknown-linux-musl -p runeward-vmagent`
   (`aarch64-unknown-linux-musl` on arm64), then
   `RUNEWARD_MICROVM_AGENT=/path/to/runeward-vmagent` (or put it next to the
   `runeward` binary).
2. e2fsprogs 1.43 or later (`mkfs.ext4` and `debugfs`; Debian's `e2fsprogs`,
   or `RUNEWARD_MICROVM_MKFS`).
3. Access to `/dev/kvm` for the user running Rune Box (the `kvm` group).
4. Firecracker: a release binary
   (`https://github.com/firecracker-microvm/firecracker/releases`, checked
   against its `.sha256.txt`) as `firecracker` on `PATH` or
   `RUNEWARD_FIRECRACKER_BIN`, and an uncompressed guest kernel with virtio
   MMIO block and vsock, ext4, overlayfs, devtmpfs and initramfs support as
   `RUNEWARD_MICROVM_KERNEL` (the Firecracker CI kernels qualify; tested:
   `firecracker-ci/v1.15/x86_64/vmlinux-6.1.155`, sha256
   `e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2`).
5. libkrun: libkrun 1.19 or later **built with block-device support**
   (`make BLK=1`; distribution packages may lack it, and the helper refuses
   such a build), libkrunfw next to it, the `runeward-krun` helper
   (`cargo build --release -p runeward-krun`) on `PATH` or
   `RUNEWARD_KRUN_HELPER`, and `RUNEWARD_LIBKRUN` pointing at
   `libkrun.so.1` when it is not on the loader path.

Settings: `RUNEWARD_MICROVM_DIR` (state and cache, default
`~/.runeward/microvm`; keep it short, Unix socket paths are limited to about
100 bytes), `RUNEWARD_MICROVM_VMM`, `RUNEWARD_MICROVM_DISK_SIZE`, and the
paths above. Opening the backend fails with a message naming what is missing.

### macOS

libkrun runs on Apple silicon through Hypervisor.framework with the same
guest design (block devices, vsock-to-Unix-socket mappings, no TSI).
Firecracker is Linux-only. A macOS host needs:

- libkrun built for macOS with block-device support
  (`cargo build --release -p libkrun --no-default-features --features blk`
  in the libkrun source; Rune Box disables libkrun's init, so the init blob
  and its Linux sysroot are not needed) and libkrunfw built from the
  release's `libkrunfw-prebuilt-aarch64.tgz`
  (`cc -fPIC -DABI_VERSION=5 -shared -o libkrunfw.5.dylib kernel.c`), side by
  side; `RUNEWARD_LIBKRUN` names `libkrun.1.dylib` and the helper finds
  libkrunfw next to it;
- the `runeward-krun` helper signed with the hypervisor entitlement:
  `codesign --force -s - --entitlements hvf.plist runeward-krun`, where
  `hvf.plist` sets `com.apple.security.hypervisor` to true;
- an `aarch64-unknown-linux-musl` build of `runeward-vmagent`;
- e2fsprogs (`mkfs.ext4` and `debugfs`, for example Homebrew's `e2fsprogs`
  via `RUNEWARD_MICROVM_MKFS`);
- `RUNEWARD_MICROVM_DIR` on a case-sensitive volume (Linux root filesystems
  contain names that differ only in case), for example a case-sensitive APFS
  disk image.

Verified on an Apple silicon Mac (macOS 27, libkrun 1.19.6 built as above,
libkrunfw 5.6.2), with one substitution: e2fsprogs was not installed, so
`mkfs.ext4` and `debugfs` ran in a Linux container through a wrapper script.
The end-to-end test passed: verdict `vm` from `kernel:separate` (guest
`6.12.109` against Darwin `27.0.0`) and the arm64 device tree
(`hypervisor:devicetree=linux,dummy-virt`; there is no `hypervisor` CPU flag
on arm64) with `host:hypervisor=libkrun`, exec and a TTY, files and export,
no route around the proxy, allowed and denied egress, the workspace across
sleep and wake, and nothing left on destroy. The supervised, read-only
`runeward-sandbox` sandbox passed too (its first disk build took about 11
minutes through the container stand-in on a busy machine).

### Verifying on a KVM host

```sh
RUNEWARD_TEST_MICROVM=firecracker \
RUNEWARD_MICROVM_DIR=/var/lib/rw-microvm \
RUNEWARD_MICROVM_AGENT=/opt/runeward/runeward-vmagent \
RUNEWARD_MICROVM_KERNEL=/opt/runeward/vmlinux-6.1.155 \
cargo test -p runeward-backend --test microvm_e2e -- --nocapture
```

(`RUNEWARD_TEST_MICROVM=libkrun` with `RUNEWARD_KRUN_HELPER` and
`RUNEWARD_LIBKRUN` for libkrun.) It creates a sandbox from
`curlimages/curl` with a deny-by-default policy allowing `example.com` and a
persistent workspace, and checks the `vm` verdict, exec (status, streams,
environment, a TTY), projected files and the workspace export, that the guest
has no network interface and no route around the proxy, that the allowed
host answers through the proxy and a denied one gets a 403, that the
workspace survives sleep and wake while `/tmp` does not, and that destroying
the sandbox leaves no monitor process, socket or file.
`RUNEWARD_TEST_MICROVM_SUPERVISED=1` adds a read-only sandbox from the
`runeward-sandbox` image under the in-sandbox supervisor: governed execs run
as the image's `sandbox` user with the supervisor's seccomp filter (Landlock
reports `unsupported`: neither guest kernel has it), the enforcement report is
read back, the root refuses writes while `/tmp` and the workspace accept
them, and no host vsock port but the egress one answers. Both monitors pass both
on the KVM test host (Firecracker 1.15.1; libkrun 1.19.6 with libkrunfw
5.6.2): a cached image boots to a running sandbox in about 3 seconds.

### Limitations

- Images are pulled anonymously from their registry; private registries and
  local-only images are not supported yet.
- zstd-compressed layers are refused; images whose layers write through an
  absolute symlink to a directory fail to unpack (writes never follow links
  out of the staging root).
- A control-plane restart leaves running VMs running and reachable, but their
  egress path (served in process, like the cooperative proxy on Docker) is
  gone until the sandbox is woken again: egress fails closed.
- Firecracker runs as the Rune Box user without its jailer; the VM boundary
  and Firecracker's seccomp filters are the isolation, not a chroot around the
  monitor.
