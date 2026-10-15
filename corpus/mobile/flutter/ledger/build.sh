#!/bin/sh
# Rebuilds one release of this set: build.sh <dart version> <dart-sdk directory> <gen_snapshot>
# The Dart SDK and the android-arm64-release gen_snapshot are the archives MANIFEST.toml pins
# for that release; check their sha256 before running them.
set -eu
cd "$(dirname "$0")"
VERSION=$1
SDK=$2
GEN_SNAPSHOT=$3
OUT="dart-$VERSION"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PLATFORM="$SDK/lib/_internal/vm_platform_strong_product.dill"
[ -f "$PLATFORM" ] || PLATFORM="$SDK/lib/_internal/vm_platform_product.dill"
cp audit_ledger.dart "$WORK/"
mkdir -p "$OUT"

"$SDK/bin/dartaotruntime" "$SDK/bin/snapshots/gen_kernel_aot.dart.snapshot" \
  --platform "$PLATFORM" --aot -Ddart.vm.product=true \
  --filesystem-scheme org-dartlang-fixture --filesystem-root "$WORK" \
  -o "$WORK/audit_ledger.aot.dill" org-dartlang-fixture:///audit_ledger.dart

"$GEN_SNAPSHOT" --deterministic --snapshot_kind=app-aot-elf \
  --elf="$OUT/audit_ledger_arm64.so" --strip \
  --save-debugging-info="$OUT/audit_ledger_arm64.symbols" \
  --print-instructions-sizes-to="$OUT/audit_ledger_arm64.sizes.json" \
  "$WORK/audit_ledger.aot.dill"

sha256sum "$WORK/audit_ledger.aot.dill" "$OUT/audit_ledger_arm64.so" \
  "$OUT/audit_ledger_arm64.symbols" "$OUT/audit_ledger_arm64.sizes.json"
