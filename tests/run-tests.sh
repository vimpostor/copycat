#!/usr/bin/env bash

set -e

echo "a" > /tmp/a
echo "b" > /tmp/b
echo "c" > /tmp/c
gcc tests/tests_general.c -o tests_general
COPYCAT="/tmp/a /tmp/b" build/copycat -- ./tests_general

gcc tests/benchmark.c -lm -o benchmark
echo -e "\nRunning benchmark without interception:"
./benchmark
echo -e "\nRunning benchmark with interception:"
COPYCAT="/tmp/a /tmp/b" build/copycat -- ./benchmark
echo -e "\nRunning benchmark with strace:"
strace --quiet=all -e openat -- ./benchmark 2>/dev/null
echo -e "\nRunning benchmark with strace --seccomp-bpf:"
strace -f --seccomp-bpf --quiet=all -e openat -- ./benchmark 2>/dev/null
