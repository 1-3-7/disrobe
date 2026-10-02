#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"
overlay_url="https://github.com/DreamSoule/ollvm17"
overlay_commit="b58debfd7f62c55f0a83ce975527f378b145ad6a"
llvm_url="https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.6/llvm-project-17.0.6.src.tar.xz"

sudo apt-get update
sudo apt-get install --yes ninja-build cmake
work=/mnt/ollvm
sudo mkdir -p "$work"
sudo chown "$(id -u):$(id -g)" "$work"
df -h "$work"

curl --fail --silent --show-error --location --output "$work/llvm.tar.xz" "$llvm_url"
llvm_sha256="$(sha256sum "$work/llvm.tar.xz" | cut -d' ' -f1)"
tar -xJf "$work/llvm.tar.xz" -C "$work"
src="$work/llvm-project-17.0.6.src"

overlay="$work/ollvm17"
git init --quiet "$overlay"
git -C "$overlay" fetch --quiet --depth 1 "$overlay_url" "$overlay_commit"
git -C "$overlay" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$overlay" rev-parse HEAD)" = "$overlay_commit"
cp -R "$overlay/llvm-project/." "$src/"

cmake -G Ninja -S "$src/llvm" -B "$work/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS=clang \
  -DLLVM_TARGETS_TO_BUILD=X86 \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF
ninja -C "$work/build" clang
clang="$work/build/bin/clang"
"$clang" --version

cat > "$OUT/tool.env" <<EOF
name=OLLVM (ollvm17 passes over LLVM 17.0.6)
url=$overlay_url
commit=$overlay_commit
tree=$(git -C "$overlay" rev-parse 'HEAD^{tree}')
version=llvm-project-17.0.6.src.tar.xz sha256 $llvm_sha256 from $llvm_url; built Release, X86 target, clang only
runtime=$("$clang" --version | head -n 1); runner glibc $(ldd --version | head -n 1)
EOF

presets=(
  "fla:-mllvm -fla"
  "bcf:-mllvm -bcf -mllvm -bcf_prob=100"
  "sub:-mllvm -sub -mllvm -sub_loop=2"
  "split:-mllvm -split -mllvm -split_num=3"
  "all:-mllvm -fla -mllvm -bcf -mllvm -bcf_prob=80 -mllvm -sub -mllvm -split -mllvm -sobf"
)
inputs=(
  corpus/native/ollvm/probe_src.c
  corpus/native/ollvm/bcf_src.c
  corpus/native/ollvm/sub_src.c
  corpus/native/obfuscators/amice/sample.c
  corpus/native/obfuscators/obfush/sample.c
)

mkdir -p "$OUT/files"
: > "$OUT/outputs.tsv"
for input in "${inputs[@]}"; do
  program="$(basename "$(dirname "$input")")-$(basename "$input" .c)"
  plain="$OUT/files/$program.plain.elf"
  if ! "$clang" -O0 -o "$plain" "$REPO/$input"; then
    printf '%s\t%s\t%s\t%s\n' - "$input" "clang -O0" input-failed >> "$OUT/outputs.tsv"
    continue
  fi
  expected="$(timeout 60 "$plain" 2>&1)" || true
  for preset in "${presets[@]}"; do
    label="${preset%%:*}"
    read -ra flags <<< "${preset#*:}"
    output="files/$program.$label.elf"
    command="clang -O0 ${preset#*:} -o $program.$label.elf $(basename "$input")"
    if timeout 1800 "$clang" -O0 "${flags[@]}" -o "$OUT/$output" "$REPO/$input"; then
      if actual="$(timeout 60 "$OUT/$output" 2>&1)" && [ "$actual" = "$expected" ]; then
        behaviour=same
      else
        behaviour=differs
        mkdir -p "$OUT/diffs"
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "${actual:-}") > "$OUT/diffs/$program.$label.txt" || true
      fi
    else
      behaviour=tool-failed
      output=-
    fi
    printf '%s\t%s\t%s\t%s\n' "$output" "$input" "$command" "$behaviour" >> "$OUT/outputs.tsv"
  done
done
