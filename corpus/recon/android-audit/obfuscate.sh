#!/bin/sh
set -eu

here="$(cd "$(dirname "$0")" && pwd)"

: "${OBFUSCAPK_SRC:?Obfuscapk checkout (the directory holding src/obfuscapk)}"
: "${OBFUSCAPK_PYTHON:?python interpreter with Obfuscapk's requirements installed}"
: "${APKTOOL_PATH:?apktool launcher}"
: "${APKSIGNER_PATH:?apksigner launcher}"
: "${ZIPALIGN_PATH:?zipalign executable}"
export APKTOOL_PATH APKSIGNER_PATH ZIPALIGN_PATH

out="$here/obfuscapk"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

ignore="$work/ignore-packages.txt"
printf 'com.google.android\n' > "$ignore"

run() {
    label="$1"
    shift
    args=""
    for o in "$@"; do
        args="$args -o $o"
    done
    rm -rf "$work/$label"
    (cd "$OBFUSCAPK_SRC/src" && "$OBFUSCAPK_PYTHON" -m obfuscapk.cli $args -i \
        --ignore-packages-file "$ignore" -w "$work/$label" \
        -d "$out/$label.apk" "$here/audit-plants.apk")
}

run strings ConstStringEncryption Rebuild NewAlignment NewSignature
run goto Goto Rebuild NewAlignment NewSignature
run reorder Reorder Rebuild NewAlignment NewSignature
run callind CallIndirection Rebuild NewAlignment NewSignature
run advreflection AdvancedReflection Rebuild NewAlignment NewSignature
run full ConstStringEncryption Reflection AdvancedReflection ArithmeticBranch Goto Nop Reorder \
    CallIndirection MethodOverload DebugRemoval ClassRename MethodRename FieldRename \
    Rebuild NewAlignment NewSignature

sha256sum "$out"/*.apk
wc -c "$out"/*.apk
