#!/usr/bin/env bash

set -e

echo "a" > /tmp/a
echo "b" > /tmp/b
echo "c" > /tmp/c
gcc tests/tests_general.c -o tests_general
COPYCAT="/tmp/a /tmp/b" build/copycat -- ./tests_general

gcc -lm tests/benchmark.c -o benchmark
echo -e "\nRunning benchmark without interception:"
./benchmark
echo -e "\nRunning benchmark with interception:"
COPYCAT="/tmp/a /tmp/b" build/copycat -- ./benchmark
