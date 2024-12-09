#!/usr/bin/env bash

set -e

COPYCAT="/tmp/a /tmp/b" copycat -- tests

echo -e "\nRunning benchmark without interception:"
benchmark
echo -e "\nRunning benchmark with interception:"
COPYCAT="/tmp/a /tmp/b" build/copycat -- benchmark
echo -e "\nRunning benchmark with strace:"
strace --quiet=all -e openat -- benchmark 2>/dev/null
echo -e "\nRunning benchmark with strace --seccomp-bpf:"
strace -f --seccomp-bpf --quiet=all -e openat -- benchmark 2>/dev/null
