#!/bin/sh
# A docker CLI whose `exec` runs the command locally (dropping exec flags and
# the container name), for exercising exec/attach plumbing.
case "$1" in
  version) echo 29.0.0 ;;
  info) echo runc ;;
  exec)
    shift
    while [ $# -gt 0 ]; do
      case "$1" in
        -w|-e) shift 2 ;;
        -i|-t) shift ;;
        *) break ;;
      esac
    done
    shift
    exec "$@" ;;
esac
