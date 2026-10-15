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

classes="$REPO/corpus/apple/src/classes"
build="$RUNNER_TEMP/classes"
mkdir -p "$build"
command="clang -target arm64-apple-ios15.0 -fobjc-arc -c Legacy.m; swiftc -target arm64-apple-ios15.0 -emit-library -module-name Fixture Views.swift Legacy.o -o Fixture.dylib"
if xcrun -sdk iphoneos clang -target arm64-apple-ios15.0 -fobjc-arc -O1 -ffile-prefix-map="$REPO"=. \
    -c "$classes/Legacy.m" -o "$build/Legacy.o" \
  && xcrun -sdk iphoneos swiftc -target arm64-apple-ios15.0 -O -file-prefix-map "$REPO"=. \
    -file-prefix-map "$RUNNER_TEMP"=/tmp -emit-library -module-name Fixture \
    "$classes/Views.swift" "$build/Legacy.o" -o "$OUT/files/Fixture.dylib" \
  && test -s "$OUT/files/Fixture.dylib"; then
  xcrun nm -m "$OUT/files/Fixture.dylib" > "$OUT/files/Fixture.dylib.nm.txt"
  xcrun nm -n -U "$OUT/files/Fixture.dylib" > "$OUT/files/Fixture.dylib.nm-defined.txt"
  xcrun otool -ov "$OUT/files/Fixture.dylib" > "$OUT/files/Fixture.dylib.otool-ov.txt"
  xcrun otool -l "$OUT/files/Fixture.dylib" > "$OUT/files/Fixture.dylib.otool-l.txt"
  xcrun swift-demangle --compact < "$OUT/files/Fixture.dylib.nm.txt" > "$OUT/files/Fixture.dylib.nm-demangled.txt"
  printf '%s\t%s\t%s\t%s\n' files/Fixture.dylib corpus/apple/src/classes "$command" same >> "$OUT/outputs.tsv"
else
  printf '%s\t%s\t%s\t%s\n' - corpus/apple/src/classes "$command" tool-failed >> "$OUT/outputs.tsv"
fi
