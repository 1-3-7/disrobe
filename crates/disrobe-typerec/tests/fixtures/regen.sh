#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
gcc -g -O0 -gdwarf-4 -fno-asynchronous-unwind-tables -nostdlib -Wl,-e,_start \
    -o types_corpus.unstripped.exe types_corpus.c
objcopy --strip-debug types_corpus.unstripped.exe types_corpus.stripped.exe
echo "regenerated types_corpus.unstripped.exe (ground truth, DWARF) and types_corpus.stripped.exe (input)"
