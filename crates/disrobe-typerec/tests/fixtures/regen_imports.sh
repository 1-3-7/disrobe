#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

gcc -O1 -nostdlib -fno-asynchronous-unwind-tables -Wl,-e,_start \
    -o imports_pe.exe imports_pe.c -lkernel32

clang -target x86_64-unknown-linux-gnu -fPIC -O0 -fno-asynchronous-unwind-tables \
    -c imports_elf.c -o imports_elf.o
ld.lld -shared -o imports_elf.so imports_elf.o
rm -f imports_elf.o

echo "regenerated imports_pe.exe (kernel32 named imports) and imports_elf.so (libc JUMP_SLOT/GLOB_DAT imports)"
