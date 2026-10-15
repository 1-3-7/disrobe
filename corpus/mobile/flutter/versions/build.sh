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
cp receipt_validator.dart "$WORK/"
mkdir -p "$OUT"

"$SDK/bin/dartaotruntime" "$SDK/bin/snapshots/gen_kernel_aot.dart.snapshot" \
  --platform "$PLATFORM" --aot -Ddart.vm.product=true \
  --filesystem-scheme org-dartlang-fixture --filesystem-root "$WORK" \
  -o "$WORK/receipt_validator.aot.dill" org-dartlang-fixture:///receipt_validator.dart

"$GEN_SNAPSHOT" --deterministic --snapshot_kind=app-aot-elf \
  --elf="$OUT/receipt_validator_arm64.so" --print_cluster_information \
  --print-instructions-sizes-to="$OUT/receipt_validator_arm64.sizes.json" \
  "$WORK/receipt_validator.aot.dill" 2> "$OUT/clusters.txt"

"$GEN_SNAPSHOT" --deterministic --snapshot_kind=app-aot-elf \
  --elf="$OUT/receipt_validator_obfuscated_arm64.so" --print_cluster_information \
  --dwarf-stack-traces --strip \
  --save-debugging-info="$OUT/receipt_validator_obfuscated_arm64.symbols" \
  --obfuscate \
  --save-obfuscation-map="$OUT/receipt_validator_obfuscated_arm64.obfuscation_map.json" \
  --print-instructions-sizes-to="$OUT/receipt_validator_obfuscated_arm64.sizes.json" \
  "$WORK/receipt_validator.aot.dill" 2> "$OUT/clusters_obfuscated.txt"

sha256sum "$WORK/receipt_validator.aot.dill" "$OUT/receipt_validator_arm64.so" \
  "$OUT/receipt_validator_obfuscated_arm64.so" "$OUT/receipt_validator_arm64.sizes.json" \
  "$OUT/receipt_validator_obfuscated_arm64.sizes.json" \
  "$OUT/receipt_validator_obfuscated_arm64.symbols" \
  "$OUT/receipt_validator_obfuscated_arm64.obfuscation_map.json"
