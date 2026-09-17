#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="${ROOT}/../obfuscator-io-high.js"
PRESETS_DIR="${ROOT}/presets"
CONTROLS_DIR="${ROOT}/controls"

if ! command -v javascript-obfuscator >/dev/null 2>&1; then
  echo "javascript-obfuscator not on PATH; install with: npm install -g javascript-obfuscator"
  exit 0
fi

mkdir -p "${PRESETS_DIR}" "${CONTROLS_DIR}"

if [[ ! -f "${SRC}" ]]; then
  cat > "${SRC}" <<'EOF'
function greet(name) {
    return "hello, " + name;
}
console.log(greet("world"));
EOF
fi

for preset in low medium high; do
  out="${PRESETS_DIR}/${preset}.js"
  javascript-obfuscator "${SRC}" --output "${out}" --options-preset "${preset}-obfuscation"
  echo "preset:${preset} -> ${out}"
done

declare -A CONTROLS
CONTROLS[booleans]="--transform-object-keys false --simplify false --compact false"
CONTROLS[controlFlowFlattening]="--control-flow-flattening true --control-flow-flattening-threshold 1"
CONTROLS[deadCodeInjection]="--dead-code-injection true --dead-code-injection-threshold 1"
CONTROLS[identifiersHexadecimal]="--identifier-names-generator hexadecimal --rename-globals true"
CONTROLS[identifiersMangled]="--identifier-names-generator mangled --rename-globals true"
CONTROLS[numbersToExpressions]="--numbers-to-expressions true"
CONTROLS[objectTransform]="--transform-object-keys true"
CONTROLS[selfDefending]="--self-defending true"
CONTROLS[stringArrayBase64]="--string-array true --string-array-encoding base64 --string-array-threshold 1"
CONTROLS[stringArrayRc4]="--string-array true --string-array-encoding rc4 --string-array-threshold 1"
CONTROLS[stringArrayShuffle]="--string-array true --string-array-shuffle true --string-array-threshold 1"
CONTROLS[stringArrayRotate]="--string-array true --string-array-rotate true --string-array-threshold 1"
CONTROLS[splitStrings]="--split-strings true --split-strings-chunk-length 4"
CONTROLS[renameProperties]="--rename-properties true --rename-properties-mode safe"
CONTROLS[debugProtection]="--debug-protection true"
CONTROLS[compact]="--compact true"
CONTROLS[unicodeEscape]="--unicode-escape-sequence true"

for name in "${!CONTROLS[@]}"; do
  out="${CONTROLS_DIR}/${name}.js"
  flags="${CONTROLS[${name}]}"
  javascript-obfuscator "${SRC}" --output "${out}" ${flags} || echo "skip:${name}"
  echo "control:${name} -> ${out}"
done

echo "done"
