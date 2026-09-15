#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${HERE}/cxx_hierarchy.cpp"

CLANGXX="${CLANGXX:-clang++}"
"${CLANGXX}" -DCXX_KEY= --target=x86_64-unknown-linux-gnu \
    -frtti -fexceptions -fno-use-cxa-atexit -fuse-ld=lld -nostdlib \
    -shared -fPIC -O1 -std=c++17 \
    -o "${HERE}/cxx_hierarchy_itanium.so" "${SRC}"

if command -v cl >/dev/null 2>&1; then
    cl //nologo //std:c++17 //GR //Od //EHsc //MD //DCXX_KEY= //DCXX_DEFS //c //Fo:defs.obj "${SRC}"
    cl //nologo //std:c++17 //GR //Od //EHsc //MD //DCXX_KEY= //DCXX_MAIN //c //Fo:main.obj "${SRC}"
    link //nologo //OUT:"${HERE}/cxx_hierarchy_msvc.exe" defs.obj main.obj
    rm -f defs.obj main.obj
fi
