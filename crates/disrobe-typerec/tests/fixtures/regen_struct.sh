#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
gcc -g -O0 -gdwarf-4 -fno-asynchronous-unwind-tables -nostdlib -Wl,-e,_start \
    -o struct_corpus.unstripped.exe struct_corpus.c
objcopy --strip-debug struct_corpus.unstripped.exe struct_corpus.stripped.exe
echo "regenerated struct_corpus.unstripped.exe (ground truth, DWARF) and struct_corpus.stripped.exe (input)"
