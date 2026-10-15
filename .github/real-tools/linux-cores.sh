#!/usr/bin/env bash
set -euo pipefail

: "${REPO:?}" "${OUT:?}"

sudo apt-get update
sudo apt-get install --yes gdb gcc

cat > "$OUT/tool.env" <<EOF
name=Linux kernel core dumps
url=https://www.kernel.org
commit=$(uname -r)
tree=$(gcc --version | head -n 1)
runtime=$(gdb --version | head -n 1)
EOF

cores="$RUNNER_TEMP/cores"
mkdir -p "$cores" "$OUT/files"
sudo sysctl -w kernel.core_pattern="$cores/core.%e.%p"
sudo sysctl -w kernel.core_uses_pid=1
ulimit -c unlimited
: > "$OUT/outputs.tsv"

for program in segv abort threads stack; do
  input="corpus/crash/linux/src/$program.c"
  test -f "$REPO/$input"
  binary="$RUNNER_TEMP/$program"
  gcc -O0 -g -pthread -fno-omit-frame-pointer -ffile-prefix-map="$REPO"=. -ffile-prefix-map="$RUNNER_TEMP"=/tmp \
    -o "$binary" "$REPO/$input"
  rm -f "$cores"/core."$program".*
  ( cd "$RUNNER_TEMP" && ulimit -c unlimited && "$binary" ) || true
  core="$(ls "$cores"/core."$program".* 2>/dev/null | head -n 1 || true)"
  command="gcc -O0 -g -pthread -fno-omit-frame-pointer -o $program $input; ./$program"
  if [ -n "$core" ] && [ -s "$core" ]; then
    cp "$core" "$OUT/files/$program.core"
    cp "$binary" "$OUT/files/$program.elf"
    gdb -batch -nx -ex 'info threads' -ex 'thread apply all bt' -ex 'info registers' -ex 'info sharedlibrary' \
      "$binary" "$core" > "$OUT/files/$program.gdb.txt" 2>&1 || true
    printf '%s\t%s\t%s\t%s\n' "files/$program.core" "$input" "$command" same >> "$OUT/outputs.tsv"
  else
    printf '%s\t%s\t%s\t%s\n' "-" "$input" "$command" tool-failed >> "$OUT/outputs.tsv"
  fi
done
