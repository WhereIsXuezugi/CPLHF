#!/usr/bin/env sh
# tools/find-port-owner.sh
#
# Given one or more port numbers, prints the on-disk path of the
# executable(s) currently bound to that port over TCP. Useful during a
# competition round for quickly answering "what process is this?" when
# `ss -tuln` shows a listener you don't recognize.
#
# Usage:
#   ./tools/find-port-owner.sh 22 80 3306
#
# Requires: fuser, awk, readlink (all present by default on Ubuntu/Debian).

set -eu

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 PORT [PORT ...]" >&2
    exit 1
fi

for port in "$@"; do
    pids=$(fuser "${port}/tcp" 2>/dev/null | awk '{ for (i = 1; i <= NF; ++i) print $i }') || true
    if [ -z "$pids" ]; then
        echo "port $port: no listener found"
        continue
    fi
    for pid in $pids; do
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "(unable to resolve, pid $pid may have exited)")
        echo "port $port: pid $pid -> $exe"
    done
done
