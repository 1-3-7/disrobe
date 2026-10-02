#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
commit="ace084c897369faf584dfa3baeea159d7b205213"
url="https://github.com/zeusssz/hercules-obfuscator"

sudo apt-get update
sudo apt-get install --yes lua5.4
lua5.4 -v

tool="$RUNNER_TEMP/hercules"
git init --quiet "$tool"
git -C "$tool" fetch --quiet --depth 1 "$url" "$commit"
git -C "$tool" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$tool" rev-parse HEAD)" = "$commit"

cat > "$OUT/tool.env" <<EOF
name=Hercules
url=$url
commit=$commit
tree=$(git -C "$tool" rev-parse 'HEAD^{tree}')
runtime=$(lua5.4 -v 2>&1)
EOF

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for program in tour values loops branches objects; do
  input="corpus/lua/behaviour/$program.lua"
  expected="$(cd "$REPO" && timeout 60 lua5.4 "$input")"
  for preset in light balanced heavy maximum; do
    work="$RUNNER_TEMP/work-$program-$preset"
    mkdir -p "$work"
    cp "$REPO/$input" "$work/$program.lua"
    command="lua5.4 hercules.lua $program.lua --$preset"
    output="files/$program.$preset.lua"
    if (cd "$tool/src" && timeout 300 lua5.4 hercules.lua "$work/$program.lua" "--$preset") \
      && test -s "$work/${program}_obfuscated.lua"; then
      cp "$work/${program}_obfuscated.lua" "$OUT/$output"
      if actual="$(cd "$REPO" && timeout 60 lua5.4 "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
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
