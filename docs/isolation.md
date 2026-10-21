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
| `kernel`    | A kernel that is not the host's: gVisor's user-space kernel, or a VM runtime's guest kernel whose hardware virtualisation the evidence could not confirm. |
| `vm`        | A hardware-virtualised guest: Kata on QEMU, Cloud Hypervisor or Firecracker. |

## Runtimes

| `runtime_class`          | What it is                                   | Name claims | At most |
|--------------------------|----------------------------------------------|-------------|---------|
| empty, `runc`, `crun`    | Engine default, shared kernel                | container   | container |
| `runsc` (`gvisor`)       | gVisor                                       | kernel      | kernel  |
| `kata`, `kata-qemu`, `kata-clh`, `io.containerd.kata[-<h>].v2` | Kata Containers, QEMU or Cloud Hypervisor | vm | vm |
| `kata-fc` (Kubernetes only) | Kata Containers with Firecracker; the workspace persists only on a direct-volume StorageClass | vm | vm |
| `krun`                   | crun built with libkrun: **refused** (no exec into a running guest) | vm | refused |

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

When a VM sandbox still fails to start with a known VM start failure
(`timed out waiting for QMP ready`, `start vm`, `failed to create shim
task`), the error names the likely causes: the guest size against the host
memory, the runtime not being able to use `/dev/kvm` (permissions, or no
nested virtualisation), or a broken hypervisor configuration
(`/etc/kata-containers/runtime-rs/configuration.toml`). A failed create
never leaves the container, the egress sidecar or the workspace volume
behind (on Kubernetes: the Pod, ConfigMap, Secret, NetworkPolicy or PVC).

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
- With `RUNEWARD_K8S_DIRECT_VOLUME_CLASS` naming a StorageClass of Kata's
  `csi-kata-directvolume` driver (built from the 4.2.0 source), the
  workspace was a 2 GiB ext4 disk at `/dev/vdd`, root-owned `1777` after the
  `workspace-perms` init container, and the image's user (uid 1000) wrote
  to it; the probe no longer reported `workspace:ephemeral=tmpfs`. The
  stock driver deletes the backing disk in NodeUnstageVolume, so the first
  sleep wiped the workspace and the wake formatted a new one; with the
  deletion moved to DeleteVolume, files survived two sleep/wake cycles and
  the init container left the handed-over root alone (its ctime did not
  change). Destroy removed the Pod, the PVC, the PV, the backing disk and
  the direct-volume mount info.
- That Pod had three of Firecracker's five drive slots in use, but Kata's
  slot counter had passed the last one (it also counts the slots the exited
  init container gave back), so the next container got none: a Charter with
  `[network] default = "deny"` (egress sidecar) failed with "add block
  device: After 500 attempts". Without the class the same Charter started
  (pause, sandbox and egress, three slots) with a tmpfs workspace, so only
  persistent workspaces use the class.
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

## Installing a runtime

`runeward runtime install <gvisor|kata|kata-fc> [--engine docker|podman|k8s] [--hypervisor qemu|clh] [--apply]`
prints host checks and the exact steps; nothing changes without `--apply`.
Without root it verifies downloads into a staging directory and prints the
`sudo` commands to finish. A failing check (for example no `/dev/kvm`)
refuses `--apply`.

Host checks for VM runtimes: Linux host, `/dev/kvm` present and openable,
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
`deploy/Dockerfile.csi-directvolume`) is Kata 4.3.0's driver with two
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

To bring your own driver instead, set `sandbox.directVolumeStorageClass` (or
`RUNEWARD_K8S_DIRECT_VOLUME_CLASS`) to its StorageClass; it needs both
changes above.

**Firecracker has five drive slots per pod.** Every container root
filesystem (the pause container and init containers included) and every
block volume takes one, and Kata 4.2.0 and 4.3.0 do not give back the slot of
an exited init container: the device manager advances its slot counter even
when it reuses a freed slot, and the Firecracker driver never detaches a
removed drive
([kata-containers#13565](https://github.com/kata-containers/kata-containers/issues/13565)).
Rune Box counts the drives a sandbox's Pod needs and refuses it before
creating anything when they exceed five; `runeward charter lint` flags the
one Charter shape that does:

| Pod | Drives |
| --- | --- |
| pause, sandbox, persistent workspace | 3 |
| + egress sidecar (`[network] default = "deny"` or a broker) | 4 |
| + strict egress init container | 5 |
| + broker trust-bundle init container (strict egress, broker and a persistent workspace) | 6: refused |

Use `kata-qemu` or `kata-clh` for that combination.

Both limits are tracked in
[#79](https://github.com/Runeeward/runeward/issues/79).

### libkrun (`krun`): refused

crun's libkrun handler boots a real microVM but cannot execute a command in
a running guest (`podman exec` fails with "the handler does not support
exec"; Docker and Kubernetes reach the same handler). Rune Box needs exec
for every command, file operation and the isolation probe, so `krun` is
refused by the Charter lint, the Docker/Podman and Kubernetes backends (a
RuntimeClass whose handler is `krun`), and `runeward runtime install`.
Use `kata-qemu` or `kata-clh` for a VM boundary on Docker or Podman.

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
"microvm"` is reserved for a future driver that boots Firecracker directly
(with a block-device workspace); it is not implemented.
