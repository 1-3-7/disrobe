#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
gem_version="0.4.2"
gem_sha256="d3cfd593d58a4ad19d0ba2892e6aaf110cb3e03b797d51df7b403a9690b690c1"
gems="$RUNNER_TEMP/jsobfu-gems"
mkdir -p "$gems"
(cd "$gems" && gem fetch jsobfu --version "$gem_version" > /dev/null)
echo "$gem_sha256  $gems/jsobfu-$gem_version.gem" | sha256sum --check
gem install --install-dir "$gems/install" --no-document "$gems/jsobfu-$gem_version.gem" > /dev/null
export GEM_PATH="$gems/install"
jsobfu="$gems/install/bin/jsobfu"
test -x "$jsobfu"

cat > "$OUT/tool.env" <<EOF
name=jsobfu
url=https://rubygems.org/gems/jsobfu/versions/$gem_version
version=jsobfu-$gem_version.gem sha256 $gem_sha256 (BSD-3-Clause)
runtime=$(ruby --version); node $(node --version)
EOF

inputs=(
  corpus/js/jsobfu/input.js
  corpus/js/hello.js
)
levels=(1 2 3)

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for input in "${inputs[@]}"; do
  program="$(basename "$input" .js)"
  expected="$(cd "$REPO" && timeout 60 node "$input" 2>&1)" || true
  for level in "${levels[@]}"; do
    output="files/$program.jsobfu$level.js"
    command="cat $program.js | jsobfu $level"
    if timeout 300 "$jsobfu" "$level" < "$REPO/$input" > "$OUT/$output" 2> "$RUNNER_TEMP/$program.$level.err" && test -s "$OUT/$output"; then
      if actual="$(timeout 60 node "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
        behaviour=same
      else
        behaviour=differs
        mkdir -p "$OUT/diffs"
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "${actual:-}") > "$OUT/diffs/$program.jsobfu$level.txt" || true
      fi
    else
      behaviour=tool-failed
      output=-
      mkdir -p "$OUT/diffs"
      cp "$RUNNER_TEMP/$program.$level.err" "$OUT/diffs/$program.jsobfu$level.tool.txt" 2>/dev/null || true
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
