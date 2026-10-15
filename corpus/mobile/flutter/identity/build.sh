#!/bin/sh
# Builds the authored Flutter identity fixtures with LLVM 19 (clang, lld, llvm-lipo) and
# prints the reference facts llvm-readobj reports for each of them.
set -eu
cd "$(dirname "$0")"
LLVM=${LLVM:-}
CC="${LLVM}clang"
LIPO=${LIPO:-llvm-lipo}
READOBJ="${LLVM}llvm-readobj"
HASH=ace654289f5abc240509fc941453ebc5
OTHER_HASH=80a49c7111088100a233b2ae788e1f48
COMMON="-O0 -nostdlib -fno-asynchronous-unwind-tables -fvisibility=hidden"
ELF="$COMMON -shared -fuse-ld=lld -Wl,--build-id=sha1"
MACHO="$COMMON -dynamiclib -fuse-ld=lld -Wl,-undefined,dynamic_lookup -install_name @rpath/Fixture"

"$CC" --target=aarch64-linux-android21 $ELF -DTARGET='"android_arm64"' -DSNAPSHOT_HASH="\"$HASH\"" -o libflutter_arm64.so src/engine.c
"$CC" --target=aarch64-linux-android21 $ELF -DTARGET='"android_arm64"' -DSNAPSHOT_HASH="\"$OTHER_HASH\"" -o libflutter_other_arm64.so src/engine.c
"$CC" --target=armv7a-linux-androideabi21 $ELF -DFEATURES='"arm android"' -o libapp_armv7.so src/app.c
"$CC" --target=armv7a-linux-androideabi21 $ELF -DTARGET='"android_arm"' -DSNAPSHOT_HASH="\"$HASH\"" -o libflutter_armv7.so src/engine.c
"$CC" --target=x86_64-linux-android21 $ELF -DFEATURES='"x64 android compressed-pointers"' -o libapp_x86_64.so src/app.c
"$CC" --target=arm64-apple-ios12.0 $MACHO -DFEATURES='"arm64 ios compressed-pointers"' -o App_ios_arm64 src/app.c
"$CC" --target=x86_64-apple-ios12.0-simulator $MACHO -DFEATURES='"x64 ios compressed-pointers"' -o App_ios_x86_64 src/app.c
"$CC" --target=arm64-apple-ios12.0 $MACHO -DTARGET='"ios_arm64"' -DSNAPSHOT_HASH="\"$HASH\"" -o Flutter_ios_arm64 src/engine.c
"$LIPO" -create App_ios_arm64 App_ios_x86_64 -output App_ios_universal
rm App_ios_x86_64

for f in libflutter_arm64.so libflutter_other_arm64.so libapp_armv7.so libflutter_armv7.so libapp_x86_64.so; do
  echo "== $f"
  "$READOBJ" --notes "$f" | grep "Build ID"
  "$READOBJ" --dyn-symbols "$f" | grep -E "Name: _kDart(Vm|Isolate)SnapshotData" || true
done
for f in App_ios_arm64 Flutter_ios_arm64 App_ios_universal; do
  echo "== $f"
  "$READOBJ" --macho-version-min --symbols "$f" | grep -E "Name: __kDart(Vm|Isolate)SnapshotData" || true
done
sha256sum libflutter_arm64.so libflutter_other_arm64.so libapp_armv7.so libflutter_armv7.so libapp_x86_64.so App_ios_arm64 Flutter_ios_arm64 App_ios_universal
