#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
commit="a4efc5f381c50ae2a111bdbb9272fa3203685be3"
url="https://github.com/prometheus-lua/Prometheus"

sudo apt-get update
sudo apt-get install --yes lua5.1
lua5.1 -v

tool="$RUNNER_TEMP/prometheus"
git init --quiet "$tool"
git -C "$tool" fetch --quiet --depth 1 "$url" "$commit"
git -C "$tool" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$tool" rev-parse HEAD)" = "$commit"

cat > "$OUT/tool.env" <<EOF
name=Prometheus
url=$url
commit=$commit
tree=$(git -C "$tool" rev-parse 'HEAD^{tree}')
runtime=$(lua5.1 -v 2>&1)
EOF

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for program in tour values loops branches objects; do
  input="corpus/lua/behaviour/$program.lua"
  if ! expected="$(cd "$REPO" && timeout 60 lua5.1 "$input" 2>&1)"; then
    continue
  fi
  for preset in Minify Weak Medium Strong; do
    work="$RUNNER_TEMP/work-$program-$preset"
    mkdir -p "$work"
    cp "$REPO/$input" "$work/$program.lua"
    command="lua5.1 cli.lua --preset $preset --Lua51 $program.lua"
    output="files/$program.$preset.lua"
    if (cd "$tool" && timeout 300 lua5.1 cli.lua --preset "$preset" --Lua51 "$work/$program.lua" --out "$work/$program.obfuscated.lua") \
      && test -s "$work/$program.obfuscated.lua"; then
      cp "$work/$program.obfuscated.lua" "$OUT/$output"
      if actual="$(cd "$REPO" && timeout 60 lua5.1 "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
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
