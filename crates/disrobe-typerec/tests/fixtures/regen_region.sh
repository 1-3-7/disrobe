#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

clang -target x86_64-unknown-linux-gnu -fno-pic -mcmodel=small -O0 -g -gdwarf-4 \
    -fdebug-compilation-dir=. -fno-asynchronous-unwind-tables -fno-builtin \
    -fcf-protection=none -c region_corpus.c -o region_corpus.o
ld.lld --no-pie -e _start -o region_corpus.unstripped.elf region_corpus.o
llvm-objcopy --strip-all region_corpus.unstripped.elf region_corpus.stripped.elf

clang -target x86_64-unknown-linux-gnu -fPIC -ftls-model=initial-exec -O1 -g -gdwarf-4 \
    -fdebug-compilation-dir=. -fno-asynchronous-unwind-tables -fno-builtin \
    -fcf-protection=none -c region_corpus.c -o region_corpus_pic.o
ld.lld -shared -o region_corpus.pic.unstripped.elf region_corpus_pic.o
llvm-objcopy --strip-all region_corpus.pic.unstripped.elf region_corpus.pic.stripped.elf

rm -f region_corpus.o region_corpus_pic.o

echo "regenerated region_corpus ELF pairs: O0 absolute addressing with local-exec TLS, O1 position independent with initial-exec TLS"
