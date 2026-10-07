#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
url="https://github.com/skidfuscatordev/skidfuscator-java-obfuscator/releases/download/2.0.11/skidfuscator.jar"
expected_sha256="${SKIDFUSCATOR_SHA256:-}"
jar_file="$RUNNER_TEMP/skidfuscator.jar"
curl --fail --silent --show-error --location --output "$jar_file" "$url"
jar_sha256="$(sha256sum "$jar_file" | cut -d' ' -f1)"
if [ -n "$expected_sha256" ] && [ "$jar_sha256" != "$expected_sha256" ]; then
  echo "skidfuscator.jar sha256 $jar_sha256 does not match the pinned $expected_sha256" >&2
  exit 1
fi

jdk="${JAVA_HOME_17_X64:?the runner image provides Temurin 17}"
java="$jdk/bin/java"
javac="$jdk/bin/javac"
jar="$jdk/bin/jar"

cat > "$OUT/tool.env" <<EOF
name=Skidfuscator Community
url=$url
version=skidfuscator.jar 2.0.11 sha256 $jar_sha256
runtime=$("$java" -version 2>&1 | head -n 1)
EOF

inputs=(
  corpus/jvm/obfuscators/jbco/gauntlet/Sample.java
  corpus/jvm/obfuscators/yguard/gauntlet/Calculator.java
  corpus/jvm/evalshapes/SwitchDispatch.java
  corpus/jvm/obfuscators/skidfuscator/Sample-src.java
)

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for input in "${inputs[@]}"; do
  program="$(basename "$input" .java)"
  program="${program%-src}"
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
  work="$RUNNER_TEMP/$program-skid"
  mkdir -p "$work"
  cp "$clean" "$work/$program.jar"
  output="files/$program.skidfuscator.jar"
  command="java -jar skidfuscator.jar obfuscate $program.jar (community defaults)"
  if (cd "$work" && timeout 900 "$java" -jar "$jar_file" obfuscate "$program.jar") \
    && produced="$(find "$work" -name '*.jar' ! -name "$program.jar" | head -n 1)" && test -n "$produced"; then
    cp "$produced" "$OUT/$output"
    if actual="$(timeout 60 "$java" -jar "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
      behaviour=same
    else
      behaviour=differs
      mkdir -p "$OUT/diffs"
      diff <(printf '%s\n' "$expected") <(printf '%s\n' "${actual:-}") > "$OUT/diffs/$program.skidfuscator.txt" || true
    fi
  else
    behaviour=tool-failed
    output=-
  fi
  printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" "$behaviour" >> "$OUT/outputs.tsv"
done
