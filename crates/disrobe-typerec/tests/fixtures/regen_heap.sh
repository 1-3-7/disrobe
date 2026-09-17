#!/bin/sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

clang -target x86_64-unknown-linux-gnu -fPIC -O0 -g -gdwarf-4 \
    -fdebug-compilation-dir=. -fno-asynchronous-unwind-tables -fno-builtin \
    -fcf-protection=none -c heap_corpus.c -o heap_corpus.o
ld.lld -shared -o heap_corpus.unstripped.so heap_corpus.o
llvm-objcopy --strip-all heap_corpus.unstripped.so heap_corpus.stripped.so

clang -target x86_64-unknown-linux-gnu -fPIC -O0 -g -gdwarf-4 \
    -fdebug-compilation-dir=. -fno-asynchronous-unwind-tables -fno-plt -fno-builtin \
    -fcf-protection=none -c heap_corpus.c -o heap_corpus_noplt.o
ld.lld -shared -o heap_corpus.noplt.unstripped.so heap_corpus_noplt.o
llvm-objcopy --strip-all heap_corpus.noplt.unstripped.so heap_corpus.noplt.stripped.so

clang -target x86_64-unknown-linux-gnu -fPIC -O2 -g -gdwarf-4 \
    -fdebug-compilation-dir=. -fno-asynchronous-unwind-tables -fno-builtin \
    -fcf-protection=none -c heap_corpus.c -o heap_corpus_o2.o
ld.lld -shared -o heap_corpus.o2.unstripped.so heap_corpus_o2.o
llvm-objcopy --strip-all heap_corpus.o2.unstripped.so heap_corpus.o2.stripped.so

clang -target x86_64-unknown-linux-gnu -fPIC -O0 -g -gdwarf-4 \
    -fdebug-compilation-dir=. -fno-asynchronous-unwind-tables -fno-builtin \
    -fcf-protection=full -c heap_corpus.c -o heap_corpus_cet.o
ld.lld -shared -z now -o heap_corpus.cet.unstripped.so heap_corpus_cet.o
llvm-objcopy --strip-all heap_corpus.cet.unstripped.so heap_corpus.cet.stripped.so

rm -f heap_corpus.o heap_corpus_noplt.o heap_corpus_o2.o heap_corpus_cet.o

echo "regenerated heap_corpus ELF pairs: O0 through the procedure linkage table, O0 with -fno-plt global offset table calls, O2 with the allocation pointer register resident, O0 with indirect branch tracking so calls land on the guarded linkage entry"
