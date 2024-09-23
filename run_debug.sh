#!/bin/sh
LSAN_OPTIONS="print_suppressions=0 suppressions=asan_raylib_leak.txt" ./build/graph $1
