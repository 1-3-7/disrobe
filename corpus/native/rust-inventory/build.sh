#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${1:?usage: build.sh <empty work directory> [artifact ...]}"
shift
: "${CARGO_AUDITABLE:?set CARGO_AUDITABLE to cargo-auditable.exe 0.7.7}"
: "${RUST_AUDIT_INFO:?set RUST_AUDIT_INFO to rust-audit-info.exe 0.5.4}"
LLVM_NM="${LLVM_NM:-$HOME/.rustup/toolchains/1.96.1-x86_64-pc-windows-msvc/lib/rustlib/x86_64-pc-windows-msvc/bin/llvm-nm.exe}"

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
if [ -n "$(ls -A "$WORK")" ]; then
  echo "work directory $WORK is not empty" >&2
  exit 1
fi
BIN="$HERE/bin"
REFERENCE="$HERE/reference"
mkdir -p "$BIN" "$REFERENCE"

SRC="$WORK/src"
mkdir -p "$SRC"
cp -r "$HERE/source/workspace" "$HERE/source/pathdep" "$SRC/"
cp -r "$HERE/source/gitdep" "$WORK/gitdep-src"
git -C "$WORK/gitdep-src" -c init.defaultBranch=main init -q
git -C "$WORK/gitdep-src" -c core.autocrlf=false add -A
GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@disrobe.invalid GIT_AUTHOR_DATE=2026-01-01T00:00:00Z \
  GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@disrobe.invalid GIT_COMMITTER_DATE=2026-01-01T00:00:00Z \
  git -C "$WORK/gitdep-src" -c core.autocrlf=false -c commit.gpgsign=false commit -q -m "gitdep 0.2.0"
git clone -q --bare "$WORK/gitdep-src" "$WORK/gitdep.git"

STUBS="$WORK/stubs"
mkdir -p "$STUBS"
for name in c m rt dl util pthread gcc_s gcc_eh; do
  printf '!<arch>\n' > "$STUBS/lib$name.a"
done
for name in System c m iconv resolv objc; do
  printf -- "--- !tapi-tbd\ntbd-version: 4\ntargets: [ x86_64-macos ]\ninstall-name: '/usr/lib/lib%s.dylib'\n...\n" "$name" > "$STUBS/lib$name.tbd"
done

export CARGO_HOME="$WORK/cargo-home"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_CONFIG_COUNT=1
GIT_CONFIG_KEY_0="url.$(cygpath -m "$WORK/gitdep.git").insteadOf"
export GIT_CONFIG_KEY_0
export GIT_CONFIG_VALUE_0="https://git.disrobe.invalid/gitdep.git"
export RUSTC_WRAPPER=
export CARGO_BUILD_RUSTC_WRAPPER=
export CARGO_INCREMENTAL=0
unset RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR

WIN_WORK="$(cygpath -w "$WORK")"
WIN_RUSTUP_HOME="$(cygpath -w "$(rustup show home)")"
WIN_CARGO_HOME="$(cygpath -w "$CARGO_HOME")"
WIN_SRC="$(cygpath -w "$SRC")"
WIN_STUBS="$(cygpath -w "$STUBS")"
REMAP="--remap-path-prefix=$WIN_WORK=/work --remap-path-prefix=$WIN_RUSTUP_HOME=/rustup --remap-path-prefix=$WIN_CARGO_HOME=/root/.cargo --remap-path-prefix=$WIN_SRC=/build"

build() {
  local artifact="$1" toolchain="$2" target="$3" profile="$4" mangling="$5" strip="$6" auditable="$7"
  local sysroot commit
  sysroot="$(rustc "+$toolchain" --print sysroot)"
  commit="$(rustc "+$toolchain" -vV | sed -n 's/^commit-hash: //p')"
  local flags="$REMAP --remap-path-prefix=$sysroot\lib\rustlib\src\rust=/rustc/$commit -C strip=$strip"
  if [ "$mangling" = v0 ]; then flags="$flags -C symbol-mangling-version=v0"; fi
  case "$target" in
    x86_64-pc-windows-msvc) flags="$flags -C link-arg=/PDBALTPATH:%_PDB% -C link-arg=/Brepro" ;;
    x86_64-unknown-linux-gnu) flags="$flags -C linker=rust-lld -C linker-flavor=ld.lld -C link-arg=--unresolved-symbols=ignore-all -C link-arg=--entry=main -L native=$WIN_STUBS" ;;
    x86_64-apple-darwin) flags="$flags -C linker=rust-lld -C linker-flavor=ld64.lld -C link-arg=-undefined -C link-arg=dynamic_lookup -L native=$WIN_STUBS" ;;
  esac
  local target_dir="$WORK/target-$artifact"
  local -a cargo_cmd=(cargo "+$toolchain")
  if [ "$auditable" = yes ]; then
    cargo_cmd=("$CARGO_AUDITABLE" auditable)
    export RUSTUP_TOOLCHAIN="$toolchain"
  else
    unset RUSTUP_TOOLCHAIN
  fi
  (
    cd "$SRC/workspace"
    RUSTFLAGS="$flags" CARGO_TARGET_DIR="$target_dir" \
      "${cargo_cmd[@]}" build --locked --bin rustinv --target "$target" --profile "$profile"
  )
  unset RUSTUP_TOOLCHAIN
  local dir="$profile"
  if [ "$profile" = dev ]; then dir=debug; fi
  local out="$target_dir/$target/$dir/rustinv"
  if [ "$target" = x86_64-pc-windows-msvc ]; then out="$out.exe"; fi
  cp "$out" "$BIN/$artifact"
  if grep -a -q -i -F -e "$WIN_WORK" -e "$(cygpath -m "$WORK")" -e "$WIN_RUSTUP_HOME" -e "$(cygpath -m "$WIN_RUSTUP_HOME")" -e 'Users\' -e 'Users/' "$BIN/$artifact"; then
    echo "$artifact embeds a build host path" >&2
    exit 1
  fi
  "$RUST_AUDIT_INFO" "$BIN/$artifact" > "$REFERENCE/$artifact.audit-info.json" 2>/dev/null || rm -f "$REFERENCE/$artifact.audit-info.json"
  if [ "$strip" != symbols ] && [ "$target" != x86_64-pc-windows-msvc ]; then
    python -I "$HERE/reference_symbols.py" "$LLVM_NM" "$BIN/$artifact" "$REFERENCE/$artifact.symbols.tsv"
  fi
  printf '%s  %s\n' "$(sha256sum "$BIN/$artifact" | cut -d' ' -f1)" "$artifact"
}

if [ ! -f "$HERE/source/workspace/Cargo.lock" ]; then
  (cd "$SRC/workspace" && cargo +1.96.1 generate-lockfile)
  cp "$SRC/workspace/Cargo.lock" "$HERE/source/workspace/Cargo.lock"
fi

for toolchain in 1.95.0 1.96.1; do
  rustc "+$toolchain" -vV > "$REFERENCE/rustc-$toolchain.txt"
done

ARTIFACTS=(
  "pe-1.95.0-release-auditable.exe 1.95.0 x86_64-pc-windows-msvc release default symbols yes"
  "pe-1.95.0-dev.exe 1.95.0 x86_64-pc-windows-msvc dev default none no"
  "elf-1.96.1-release-auditable.elf 1.96.1 x86_64-unknown-linux-gnu release default debuginfo yes"
  "elf-1.96.1-release-stripped.elf 1.96.1 x86_64-unknown-linux-gnu release default symbols no"
  "elf-1.96.1-dev-v0.elf 1.96.1 x86_64-unknown-linux-gnu dev v0 debuginfo no"
  "macho-1.96.1-release-auditable.macho 1.96.1 x86_64-apple-darwin release v0 debuginfo yes"
)
for spec in "${ARTIFACTS[@]}"; do
  read -r artifact toolchain target profile mangling strip auditable <<< "$spec"
  if [ "$#" -gt 0 ] && ! printf '%s\n' "$@" | grep -qx "$artifact"; then
    continue
  fi
  build "$artifact" "$toolchain" "$target" "$profile" "$mangling" "$strip" "$auditable"
done
