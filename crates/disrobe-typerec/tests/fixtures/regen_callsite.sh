#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

clang -target x86_64-unknown-linux-gnu -fPIC -O0 -g -gdwarf-4 \
    -fno-asynchronous-unwind-tables -fno-plt -fno-builtin -fcf-protection=none \
    -c callsite_corpus.c -o callsite_corpus.o
ld.lld -shared -o callsite_corpus.unstripped.so callsite_corpus.o
objcopy --strip-debug callsite_corpus.unstripped.so callsite_corpus.stripped.so
rm -f callsite_corpus.o

echo "regenerated callsite_corpus.unstripped.so (ground truth, DWARF) and callsite_corpus.stripped.so (input: .text + dynamic imports)"
