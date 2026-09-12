#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
clang --target=x86_64-w64-mingw32 -g -O1 -fno-omit-frame-pointer -gdwarf-4 \
    -fno-asynchronous-unwind-tables -nostdlib -Wl,-e_start \
    -o types_o1_corpus.unstripped.exe types_o1_corpus.c
objcopy --strip-debug types_o1_corpus.unstripped.exe types_o1_corpus.stripped.exe
echo "regenerated types_o1_corpus.unstripped.exe (ground truth, DWARF) and types_o1_corpus.stripped.exe (input)"
