#!/usr/bin/env bash

echo "a" > /tmp/a
echo "b" > /tmp/b
gcc tests/tests_general.c -o tests_general
COPYCAT="/tmp/a /tmp/b" build/copycat -- ./tests_general
