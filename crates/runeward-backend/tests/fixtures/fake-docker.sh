#!/bin/sh
# Stand-in for the docker/podman CLI used by the argv golden tests. It
# appends each invocation to $FAKE_DOCKER_LOG (default: calls.log next to
# the invoked path), with arguments separated by 0x1f and one invocation per
# line, and answers the handful of queries the backend makes. Tar streams
# piped into `exec -i ... tar -xf -` are saved next to the log as
# <log>.tar.<n>; `exec ... tar -cf -` emits a tar of $FAKE_DOCKER_EXPORT_DIR
# (default: the directory named in export_dir next to the invoked path).
# Archives piped into `cp - <ctr>:<dir>` are saved as <log>.cp.<n>.
# `info` prints the file `info` next to the invoked path when present (else
# "runc"); the isolation probe prints the file `probe` when present.
# A file `fail.<subcommand>` next to the invoked path makes that subcommand
# (`run`, `create`, `start`, ...) print the file's first line on stderr and
# exit 125; when `fail.<subcommand>.match` exists too, only invocations
# whose arguments contain its first line fail.
here=$(dirname "$0")
log="${FAKE_DOCKER_LOG:-$here/calls.log}"
if [ -z "$FAKE_DOCKER_EXPORT_DIR" ] && [ -f "$here/export_dir" ]; then
  FAKE_DOCKER_EXPORT_DIR=$(cat "$here/export_dir")
fi
for a in "$@"; do printf '%s\037' "$a" >> "$log"; done
printf '\n' >> "$log"
if [ -f "$here/fail.$1" ]; then
  if [ ! -f "$here/fail.$1.match" ] || case "$*" in *"$(head -n 1 "$here/fail.$1.match")"*) true ;; *) false ;; esac; then
    head -n 1 "$here/fail.$1" >&2
    exit 125
  fi
fi
case "$1" in
  version) echo "29.0.0" ;;
  info)
    if [ -f "$here/info" ]; then cat "$here/info"; else echo "runc"; fi ;;
  inspect)
    case "$*" in
      *State.Running*) echo true ;;
      *Config.WorkingDir*) echo "${FAKE_DOCKER_WORKDIR:-/workspace}" ;;
      *runeward.volume*) echo "runeward-vol-fake" ;;
      *IPAddress*) echo "172.17.0.9" ;;
      *) echo "deadbeef" ;;
    esac ;;
  logs) echo "transparent proxy listening on :15001" ;;
  cp)
    if [ "$2" = "-" ]; then
      n=0
      while [ -e "$log.cp.$n" ]; do n=$((n + 1)); done
      cat > "$log.cp.$n"
    fi ;;
  exec)
    case "$*" in
      *runeward-isolation-probe*)
        if [ -f "$here/probe" ]; then cat "$here/probe"; fi ;;
      *"-xf -"*)
        n=0
        while [ -e "$log.tar.$n" ]; do n=$((n + 1)); done
        cat > "$log.tar.$n" ;;
      *"-cf -"*)
        if [ -n "$FAKE_DOCKER_EXPORT_DIR" ]; then tar -C "$FAKE_DOCKER_EXPORT_DIR" -cf - .; fi ;;
    esac ;;
esac
exit 0
