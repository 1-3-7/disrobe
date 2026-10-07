#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
url="https://github.com/Guardsquare/proguard/releases/download/v7.10.0/proguard-7.10.0.tar.gz"
sha256="fbff4dfe037d0724ff767ad555c06ebd14063ccf99a657cf05a69e6f2610da21"
archive="$RUNNER_TEMP/proguard.tar.gz"
curl --fail --silent --show-error --location --output "$archive" "$url"
echo "$sha256  $archive" | sha256sum --check
tar -xzf "$archive" -C "$RUNNER_TEMP"
proguard="$RUNNER_TEMP/proguard-7.10.0/bin/proguard.sh"
test -x "$proguard" || chmod +x "$proguard"

jdk="${JAVA_HOME_17_X64:?the runner image provides Temurin 17}"
export JAVA_HOME="$jdk"
java="$jdk/bin/java"
javac="$jdk/bin/javac"
jar="$jdk/bin/jar"

cat > "$OUT/tool.env" <<EOF
name=ProGuard
url=$url
version=proguard-7.10.0.tar.gz sha256 $sha256
runtime=$("$java" -version 2>&1 | head -n 1)
EOF

presets=(
  "rename:-dontoptimize -dontshrink"
  "optimize:-optimizationpasses 3 -allowaccessmodification"
  "aggressive:-optimizationpasses 5 -allowaccessmodification -overloadaggressively -repackageclasses '' -mergeinterfacesaggressively"
)
inputs=(
  corpus/jvm/obfuscators/jbco/gauntlet/Sample.java
  corpus/jvm/obfuscators/yguard/gauntlet/Calculator.java
  corpus/jvm/evalshapes/SwitchDispatch.java
  corpus/jvm/megafile/EdgeCases.java
)

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for input in "${inputs[@]}"; do
  program="$(basename "$input" .java)"
  package="$(sed -n 's/^package \([A-Za-z0-9_.]*\);.*/\1/p' "$REPO/$input" | head -n 1)"
  class_name="$(sed -n 's/^public \(final \)\?class \([A-Za-z0-9_]*\).*/\2/p' "$REPO/$input" | head -n 1)"
  main="${package:+$package.}${class_name:-$program}"
  classes="$RUNNER_TEMP/$program-classes"
  mkdir -p "$classes"
  if ! "$javac" -source 8 -target 8 -d "$classes" "$REPO/$input"; then
    printf '%s\t%s\t%s\t%s\n' - "$input" "javac -source 8 -target 8" input-failed >> "$OUT/outputs.tsv"
    continue
  fi
  clean="$OUT/files/$program.clean.jar"
  (cd "$classes" && "$jar" cfe "$clean" "$main" .)
  expected="$(timeout 60 "$java" -jar "$clean" 2>&1)" || true
  for preset in "${presets[@]}"; do
    label="${preset%%:*}"
    options="${preset#*:}"
    work="$RUNNER_TEMP/$program-$label"
    mkdir -p "$work"
    cat > "$work/$program.pro" <<EOF
-injars $clean
-outjars $work/$program.$label.jar
-libraryjars $jdk/jmods/java.base.jmod(!**.jar;!module-info.class)
-printmapping $work/$program.$label.mapping.txt
-keep public class $main { public static void main(java.lang.String[]); }
-dontwarn
-verbose
$options
EOF
    output="files/$program.$label.jar"
    command="proguard.sh @$program.pro ($options; -keep main; mapping kept)"
    if timeout 900 "$proguard" "@$work/$program.pro" > "$work/proguard.log" 2>&1 && test -s "$work/$program.$label.jar"; then
      cp "$work/$program.$label.jar" "$OUT/$output"
      cp "$work/$program.$label.mapping.txt" "$OUT/files/$program.$label.mapping.txt"
      if actual="$(timeout 60 "$java" -jar "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
        behaviour=same
      else
        behaviour=differs
        mkdir -p "$OUT/diffs"
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "${actual:-}") > "$OUT/diffs/$program.$label.txt" || true
      fi
    else
      behaviour=tool-failed
      output=-
      mkdir -p "$OUT/diffs"
      tail -n 40 "$work/proguard.log" > "$OUT/diffs/$program.$label.tool.txt" || true
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
