#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"

venv="$RUNNER_TEMP/pyc-zipper-venv"
python3 -m venv "$venv"
cat > "$RUNNER_TEMP/requirements.txt" <<'EOF'
pyc-zipper==1.0.8 --hash=sha256:06318cca1763711be2f09f10fc0e06eafb8006b820f48ac922ddfcb677b58a61
pyobject==1.3.5.3 --hash=sha256:179801d3a55b0346c80b00559f231898149ee43efd3cf22032148cebc61990a5
EOF
"$venv/bin/pip" install --quiet --require-hashes --no-deps -r "$RUNNER_TEMP/requirements.txt"
python="$venv/bin/python"

cat > "$OUT/tool.env" <<EOF
name=pyc-zipper
url=https://pypi.org/project/pyc-zipper/1.0.8/
version=pyc-zipper 1.0.8 sdist sha256 06318cca1763711be2f09f10fc0e06eafb8006b820f48ac922ddfcb677b58a61; pyobject 1.3.5.3 cp312 manylinux wheel sha256 179801d3a55b0346c80b00559f231898149ee43efd3cf22032148cebc61990a5
runtime=$("$python" -VV)
EOF

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
inputs=(
  corpus/python/pyc_zipper/sample.py
  corpus/python/decompile/authored/bank_account_ledger.py
  corpus/python/decompile/authored/closures_nonlocal_global.py
  corpus/python/decompile/authored/class_inheritance_super.py
  corpus/python/decompile/authored/generators_yield_from.py
  corpus/python/decompile/authored/expression_evaluator.py
)
modes=(
  "zlib:--compress-module zlib --no-obfuscation"
  "bz2:--compress-module bz2 --no-obfuscation"
  "lzma:--compress-module lzma --no-obfuscation"
  "obfuscate:--obfuscate"
  "obfuscate_lzma:--obfuscate --compress-module lzma"
)
for input in "${inputs[@]}"; do
  program="$(basename "$input" .py)"
  expected="$(cd "$REPO" && timeout 60 "$python" "$input" 2>&1)"
  for mode in "${modes[@]}"; do
    label="${mode%%:*}"
    flags="${mode#*:}"
    work="$RUNNER_TEMP/work-$program-$label"
    mkdir -p "$work"
    cp "$REPO/$input" "$work/$program.py"
    command="pyc-zipper $flags $program.py"
    output="files/$program.$label.pyc"
    read -ra flagv <<< "$flags"
    if (cd "$work" && timeout 300 "$venv/bin/pyc-zipper" "${flagv[@]}" "$program.py") \
      && produced="$(find "$work" -name '*.pyc' -newer "$work/$program.py" | sort | head -n 1)" \
      && test -n "$produced"; then
      cp "$produced" "$OUT/$output"
      if actual="$(cd "$REPO" && timeout 60 "$python" "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
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
