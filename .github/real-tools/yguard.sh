#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
url="https://github.com/yWorks/yGuard/releases/download/5.0.0/yguard-bundle-5.0.0.zip"
sha256="e9ee043e9bffab6631d290ce60732929f484a541c42b8a466ef6267f1318712c"
archive="$RUNNER_TEMP/yguard.zip"
curl --fail --silent --show-error --location --output "$archive" "$url"
echo "$sha256  $archive" | sha256sum --check
mkdir -p "$RUNNER_TEMP/yguard"
unzip -q "$archive" -d "$RUNNER_TEMP/yguard"
yguard_jar="$(find "$RUNNER_TEMP/yguard" -name 'yguard-5.0.0.jar' | head -n 1)"
test -n "$yguard_jar"

jdk="${JAVA_HOME_17_X64:?the runner image provides Temurin 17}"
export JAVA_HOME="$jdk"
java="$jdk/bin/java"
javac="$jdk/bin/javac"
jar="$jdk/bin/jar"
ant --version

cat > "$OUT/tool.env" <<EOF
name=yGuard
url=$url
version=yguard-bundle-5.0.0.zip sha256 $sha256; yguard-5.0.0.jar sha256 $(sha256sum "$yguard_jar" | cut -d' ' -f1)
runtime=$("$java" -version 2>&1 | head -n 1); $(ant -version 2>&1 | head -n 1)
EOF

presets=(
  "rename:<rename logfile=\"@LOG@\" replaceClassNameStrings=\"true\"><property name=\"naming-scheme\" value=\"mix\"/></rename>"
  "shrink-rename:<shrink logfile=\"@SHRINKLOG@\"/><rename logfile=\"@LOG@\" replaceClassNameStrings=\"true\"><property name=\"naming-scheme\" value=\"small\"/><property name=\"obfuscation-prefix\" value=\"y\"/></rename>"
  "linenumbers:<rename logfile=\"@LOG@\" conservemanifest=\"true\"><property name=\"naming-scheme\" value=\"best\"/><property name=\"language-conformity\" value=\"illegal\"/><map/><adjust replaceContent=\"true\"/></rename>"
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
    body="${preset#*:}"
    work="$RUNNER_TEMP/$program-$label"
    mkdir -p "$work"
    out_jar="$work/$program.$label.jar"
    log="$work/$program.$label.renamelog.xml"
    shrinklog="$work/$program.$label.shrinklog.xml"
    body="${body//@LOG@/$log}"
    body="${body//@SHRINKLOG@/$shrinklog}"
    cat > "$work/build.xml" <<EOF
<project name="$program-$label" default="obfuscate" basedir=".">
  <taskdef name="yguard" classname="com.yworks.yguard.YGuardTask" classpath="$yguard_jar"/>
  <target name="obfuscate">
    <yguard>
      <inoutpair in="$clean" out="$out_jar"/>
      <externalclasses><pathelement location="$jdk/jmods/java.base.jmod"/></externalclasses>
      <attribute name="LineNumberTable,SourceFile"/>
      $body
    </yguard>
  </target>
</project>
EOF
    python3 - "$work/build.xml" "$main" <<'PY'
import sys
path, main = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
keep = f'<keep><class name="{main}" methods="public"/></keep>'
for tag in ("<rename", "<shrink"):
    marker = text.find(tag)
    if marker != -1:
        close = text.find(">", marker) + 1
        text = text[:close] + keep + text[close:]
open(path, "w", encoding="utf-8").write(text)
PY
    output="files/$program.$label.jar"
    command="ant -f build.xml (yguard ${label}; keep main class public methods)"
    if (cd "$work" && timeout 900 ant -q -f build.xml > "$work/ant.log" 2>&1) && test -s "$out_jar"; then
      cp "$out_jar" "$OUT/$output"
      cp "$log" "$OUT/files/$program.$label.renamelog.xml" 2>/dev/null || true
      cp "$shrinklog" "$OUT/files/$program.$label.shrinklog.xml" 2>/dev/null || true
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
      tail -n 40 "$work/ant.log" > "$OUT/diffs/$program.$label.tool.txt" || true
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
