#!/bin/sh
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
jar_out="$here/../../../crates/disrobe-pass-jvm/tests/fixtures/dexguard/DexGuardReflectStrings.jar"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

: "${R8_JAR:?set R8_JAR to a com.android.tools:r8 jar, e.g. https://dl.google.com/dl/android/maven2/com/android/tools/r8/9.1.31/r8-9.1.31.jar}"

mkdir -p "$out/classes" "$out/dex"

javac --release 11 -d "$out/classes" "$here/DexGuardReflectStrings.java"

java -cp "$R8_JAR" com.android.tools.r8.D8 \
  --release --min-api 21 \
  --output "$out/dex" \
  "$out/classes/com/disrobe/sample/DexGuardReflectStrings.class"

cp "$out/dex/classes.dex" "$here/DexGuardReflectStrings.dex"

jar --create --file "$jar_out" \
  --main-class com.disrobe.sample.DexGuardReflectStrings \
  -C "$out/classes" com

java -cp "$jar_out" com.disrobe.sample.DexGuardReflectStrings

sha256sum "$here/DexGuardReflectStrings.dex" "$jar_out"
wc -c "$here/DexGuardReflectStrings.dex" "$jar_out"
