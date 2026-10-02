#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
wheel_sha256="29d517a2248e4b441d7068a5765307139d52d02597a54a36510b224fa8bc04a0"

venv="$RUNNER_TEMP/pyobfus-venv"
python3 -m venv "$venv"
downloads="$RUNNER_TEMP/pyobfus-downloads"
"$venv/bin/pip" download --quiet --only-binary=:all: --dest "$downloads" pyobfus==0.5.30
echo "$wheel_sha256  $downloads/pyobfus-0.5.30-py3-none-any.whl" | sha256sum --check
"$venv/bin/pip" install --quiet --no-index --find-links "$downloads" pyobfus==0.5.30
python="$venv/bin/python"

cat > "$OUT/tool.env" <<EOF
name=pyobfus
url=https://pypi.org/project/pyobfus/0.5.30/
version=pyobfus 0.5.30 wheel sha256 $wheel_sha256; installed set: $(cd "$downloads" && sha256sum ./*.whl | sed 's#  \./# #' | tr '\n' ';')
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
for input in "${inputs[@]}"; do
  program="$(basename "$input" .py)"
  expected="$(cd "$REPO" && timeout 60 "$python" "$input" 2>&1)"
  for preset in safe balanced aggressive; do
    work="$RUNNER_TEMP/work-$program-$preset"
    mkdir -p "$work"
    cp "$REPO/$input" "$work/$program.py"
    command="pyobfus $program.py -o $program.$preset.py --preset $preset"
    output="files/$program.$preset.py"
    if (cd "$work" && timeout 300 "$venv/bin/pyobfus" "$program.py" -o "$program.$preset.py" --preset "$preset") \
      && test -s "$work/$program.$preset.py"; then
      cp "$work/$program.$preset.py" "$OUT/$output"
      if actual="$(cd "$REPO" && timeout 60 "$python" "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
        behaviour=same
      else
        behaviour=differs
        mkdir -p "$OUT/diffs"
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "${actual:-}") > "$OUT/diffs/$program.$preset.txt" || true
      fi
    else
      behaviour=tool-failed
      output=-
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
