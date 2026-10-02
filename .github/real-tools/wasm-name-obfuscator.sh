#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
commit="d752a3ded5638b94d4db4630ade0d1b8d3c01fb1"
url="https://github.com/abcxff/wasm-name-obfuscator"
tools_url="https://github.com/bytecodealliance/wasm-tools/releases/download/v1.250.0/wasm-tools-1.250.0-x86_64-linux.tar.gz"
tools_sha256="b746c34e7c4162b8812eb29397ebe076834e496a8c46fe68d793379a2741eb50"

curl --fail --silent --show-error --location --output "$RUNNER_TEMP/wasm-tools.tar.gz" "$tools_url"
echo "$tools_sha256  $RUNNER_TEMP/wasm-tools.tar.gz" | sha256sum --check
tar -xzf "$RUNNER_TEMP/wasm-tools.tar.gz" -C "$RUNNER_TEMP"
wasm_tools="$RUNNER_TEMP/wasm-tools-1.250.0-x86_64-linux/wasm-tools"

tool="$RUNNER_TEMP/wasm-name-obfuscator"
git init --quiet "$tool"
git -C "$tool" fetch --quiet --depth 1 "$url" "$commit"
git -C "$tool" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$tool" rev-parse HEAD)" = "$commit"

cat > "$OUT/tool.env" <<EOF
name=wasm-name-obfuscator
url=$url
commit=$commit
tree=$(git -C "$tool" rev-parse 'HEAD^{tree}')
runtime=node $(node --version); $("$wasm_tools" --version)
EOF

cat > "$RUNNER_TEMP/run-obfuscator.js" <<'EOF'
const fs = require("fs");
const obfuscate = require(process.argv[2]);
fs.writeFileSync(process.argv[5], obfuscate(fs.readFileSync(process.argv[3]), process.argv[4]));
EOF

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for input in "$REPO"/corpus/wasm/obf/real/*.clean.wat; do
  relative="${input#"$REPO"/}"
  program="$(basename "$input" .clean.wat)"
  clean="$OUT/files/$program.clean.wasm"
  "$wasm_tools" parse "$input" -o "$clean"
  "$wasm_tools" strip --all "$clean" -o "$RUNNER_TEMP/$program.stripped.wasm"
  for style in hex alphanumeral alternating; do
    output="files/$program.$style.wasm"
    command="node run-obfuscator.js obfuscate.js $program.clean.wasm $style $program.$style.wasm"
    if node "$RUNNER_TEMP/run-obfuscator.js" "$tool/obfuscate.js" "$clean" "$style" "$OUT/$output" \
      && "$wasm_tools" validate "$OUT/$output"; then
      "$wasm_tools" print "$OUT/$output" > "$OUT/files/$program.$style.wat"
      "$wasm_tools" strip --all "$OUT/$output" -o "$RUNNER_TEMP/$program.$style.stripped.wasm"
      if cmp --silent "$RUNNER_TEMP/$program.stripped.wasm" "$RUNNER_TEMP/$program.$style.stripped.wasm"; then
        behaviour=same
      else
        behaviour=differs
      fi
    else
      behaviour=tool-failed
      output=-
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$relative" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
