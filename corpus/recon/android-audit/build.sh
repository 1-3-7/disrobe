#!/bin/sh
set -eu

here="$(cd "$(dirname "$0")" && pwd)"

: "${ANDROID_FRAMEWORK_JAR:?full framework jar for javac (org.robolectric:android-all:14-robolectric-10818077)}"
: "${ANDROID_PLATFORM_JAR:?platform jar carrying resources.arsc and org.apache.http (com.google.android:android:4.1.1.4)}"
: "${ANDROID_BUILD_TOOLS:?Android build-tools directory with aapt2, zipalign and lib/d8.jar, lib/apksigner.jar}"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) sep=';' ;;
    *) sep=':' ;;
esac

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

store_pass="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
keytool -genkeypair -keystore "$out/fixture.jks" -storepass "$store_pass" -keypass "$store_pass" \
    -alias audit -dname "CN=Disrobe Audit Fixture" -keyalg RSA -keysize 2048 -validity 3650

for class in ${*:-Plants Control Flows}; do
    lower="$(printf '%s' "$class" | tr 'A-Z' 'a-z')"
    work="$out/$lower"
    mkdir -p "$work/classes" "$work/dex"

    javac --release 8 -Xlint:-options -nowarn \
        -cp "$ANDROID_FRAMEWORK_JAR$sep$ANDROID_PLATFORM_JAR" \
        -d "$work/classes" "$here/src/com/planted/audit/$class.java" \
        "$here/src/com/google/android/play/core/integrity/IntegrityManager.java" \
        "$here/src/com/google/android/gms/safetynet/SafetyNetClient.java"

    java -cp "$ANDROID_BUILD_TOOLS/lib/d8.jar" com.android.tools.r8.D8 \
        --release --min-api 21 --output "$work/dex" $(find "$work/classes" -name '*.class')

    "$ANDROID_BUILD_TOOLS/aapt2" compile -o "$work/res.zip" --dir "$here/res"
    "$ANDROID_BUILD_TOOLS/aapt2" link -o "$work/base.apk" -I "$ANDROID_PLATFORM_JAR" \
        --manifest "$here/AndroidManifest.xml" "$work/res.zip"

    (cd "$work/dex" && jar --update --no-manifest --file "$work/base.apk" classes.dex)
    if [ "$class" = Native ]; then
        (cd "$here/native" && jar --update --no-manifest --file "$work/base.apk" lib)
    fi
    "$ANDROID_BUILD_TOOLS/zipalign" -f 4 "$work/base.apk" "$work/aligned.apk"

    java -jar "$ANDROID_BUILD_TOOLS/lib/apksigner.jar" sign \
        --ks "$out/fixture.jks" --ks-pass "pass:$store_pass" --key-pass "pass:$store_pass" \
        --ks-key-alias audit --out "$here/audit-$lower.apk" "$work/aligned.apk"

    java -jar "$ANDROID_BUILD_TOOLS/lib/apksigner.jar" verify "$here/audit-$lower.apk"
done

sha256sum "$here"/audit-*.apk
wc -c "$here"/audit-*.apk
