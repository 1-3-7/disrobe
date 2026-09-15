#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
gcc -g -O0 -gdwarf-4 -fno-asynchronous-unwind-tables -nostdlib -Wl,-e,_start \
    -o abi_corpus.unstripped.exe abi_corpus.c
objcopy --strip-debug abi_corpus.unstripped.exe abi_corpus.stripped.exe
echo "regenerated abi_corpus.unstripped.exe (ground truth, DWARF) and abi_corpus.stripped.exe (input)"
