#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"

src="$REPO/corpus/apple/src"
test -d "$src"

cat > "$OUT/tool.env" <<EOF
name=Xcode actool, ibtool, assetutil and Foundation
url=https://developer.apple.com/xcode/
commit=$(xcodebuild -version | tr '\n' ' ')
tree=$(sw_vers -productVersion)
runtime=$(xcrun --show-sdk-version --sdk iphoneos)
EOF

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"

catalog="$RUNNER_TEMP/catalog"
mkdir -p "$catalog"
command="xcrun actool --compile <out> --platform iphoneos --minimum-deployment-target 15.0 Assets.xcassets"
if xcrun actool --output-format human-readable-text --notices --warnings \
    --compile "$catalog" --platform iphoneos --minimum-deployment-target 15.0 \
    --app-icon AppIcon --output-partial-info-plist "$catalog/partial.plist" \
    "$src/Assets.xcassets" && test -s "$catalog/Assets.car"; then
  cp "$catalog/Assets.car" "$OUT/files/Assets.car"
  xcrun assetutil --info "$OUT/files/Assets.car" > "$OUT/files/Assets.car.assetutil.json"
  printf '%s\t%s\t%s\t%s\n' files/Assets.car corpus/apple/src/Assets.xcassets "$command" same >> "$OUT/outputs.tsv"
else
  printf '%s\t%s\t%s\t%s\n' - corpus/apple/src/Assets.xcassets "$command" tool-failed >> "$OUT/outputs.tsv"
fi

for interface in Controls Settings; do
  input="corpus/apple/src/$interface.xib"
  output="files/$interface.nib"
  command="xcrun ibtool --compile $interface.nib $interface.xib"
  if xcrun ibtool --errors --warnings --compile "$OUT/$output" "$REPO/$input" && test -e "$OUT/$output"; then
    printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" same >> "$OUT/outputs.tsv"
  else
    printf '%s\t%s\t%s\t%s\n' - "$input" "$command" tool-failed >> "$OUT/outputs.tsv"
  fi
done

input="corpus/apple/src/archive.swift"
command="swift archive.swift <out>"
if swift "$REPO/$input" "$OUT/files" && test -s "$OUT/files/graph.archive"; then
  printf '%s\t%s\t%s\t%s\n' files/graph.archive "$input" "$command" same >> "$OUT/outputs.tsv"
else
  printf '%s\t%s\t%s\t%s\n' - "$input" "$command" tool-failed >> "$OUT/outputs.tsv"
fi
