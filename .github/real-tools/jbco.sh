#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
url="https://repo1.maven.org/maven2/org/soot-oss/soot/4.7.1/soot-4.7.1-jar-with-dependencies.jar"
sha256="7389c0e6324445af4a5eee6d8b7cd7c73c3daf1cc7effab8dc5570f0953a6079"
soot="$RUNNER_TEMP/soot.jar"
curl --fail --silent --show-error --location --output "$soot" "$url"
echo "$sha256  $soot" | sha256sum --check

jdk="${JAVA_HOME_8_X64:?the runner image provides Temurin 8}"
java="$jdk/bin/java"
javac="$jdk/bin/javac"
jar="$jdk/bin/jar"

cat > "$OUT/tool.env" <<EOF
name=JBCO (Soot soot.jbco.Main)
url=$url
version=Soot 4.7.1 jar-with-dependencies sha256 $sha256
runtime=$("$java" -version 2>&1 | tr '\n' ' ')
EOF

presets=(
  "names:-t:9:wjtp.jbco_cr -t:9:wjtp.jbco_mr -t:9:wjtp.jbco_fr"
  "flow:-t:9:jtp.jbco_adss -t:9:jtp.jbco_gia -t:9:bb.jbco_iii -t:9:bb.jbco_ctbcb -t:9:bb.jbco_rds"
  "all:-t:9:wjtp.jbco_cr -t:9:wjtp.jbco_mr -t:9:wjtp.jbco_fr -t:9:jtp.jbco_adss -t:9:jtp.jbco_gia -t:9:bb.jbco_iii -t:9:bb.jbco_ctbcb -t:9:bb.jbco_rds -t:9:bb.jbco_cb2ji -t:9:bb.jbco_rlaii"
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
  main="${package:+$package.}$program"
  classes="$RUNNER_TEMP/$program-classes"
  mkdir -p "$classes"
  if ! "$javac" -source 8 -target 8 -d "$classes" "$REPO/$input"; then
    printf '%s\t%s\t%s\t%s\n' - "$input" "javac -source 8 -target 8" input-failed >> "$OUT/outputs.tsv"
    continue
  fi
  (cd "$classes" && "$jar" cf "$OUT/files/$program.clean.jar" .)
  expected="$(timeout 60 "$java" -cp "$classes" "$main" 2>&1)"
  for preset in "${presets[@]}"; do
    label="${preset%%:*}"
    read -ra transforms <<< "${preset#*:}"
    obfuscated="$RUNNER_TEMP/$program-$label"
    output="files/$program.$label.jar"
    command="java -cp soot.jar soot.jbco.Main -cp <classes>:<rt.jar> -process-dir <classes> -d <out> ${preset#*:}"
    if timeout 600 "$java" -cp "$soot" soot.jbco.Main \
        -cp "$classes:$jdk/jre/lib/rt.jar" -process-dir "$classes" -d "$obfuscated" \
        -allow-phantom-refs "${transforms[@]}" \
      && (cd "$obfuscated" && "$jar" cf "$OUT/$output" .); then
      if actual="$(timeout 60 "$java" -cp "$obfuscated" "$main" 2>&1)" && [ "$actual" = "$expected" ]; then
        behaviour=same
      else
        behaviour=differs
      fi
    else
      behaviour=tool-failed
      output=-
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
