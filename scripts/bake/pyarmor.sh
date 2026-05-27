#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
OUT_ROOT=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --out=*) OUT_ROOT="${arg#--out=}" ;;
        -h|--help)
            echo "usage: $(basename "$0") [--dry-run] [--out=DIR]"
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
[[ -z "${OUT_ROOT}" ]] && OUT_ROOT="${REPO_ROOT}/corpus/python/pyarmor"
VENV_ROOT="${REPO_ROOT}/.developer/venv"

log_plan() { echo "[plan] $*"; }
log_run()  { echo "[run]  $*"; }
log_skip() { echo "[skip] $*"; }
log_ok()   { echo "[ok]   $*"; }
has_cmd()  { command -v "$1" >/dev/null 2>&1; }

new_pyvenv() {
    local path="$1"
    local pyarmor_ver="$2"
    if [[ -d "$path" ]]; then
        log_skip "venv already exists: $path"
        return 0
    fi
    if ! has_cmd python3 && ! has_cmd python; then
        echo "python not on PATH; cannot build pyarmor venv" >&2
        exit 1
    fi
    local py; py="$(command -v python3 || command -v python)"
    log_run "creating venv $path with pyarmor==$pyarmor_ver"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    "$py" -m venv "$path"
    local pip="${path}/bin/pip"
    [[ -x "$pip" ]] || pip="${path}/Scripts/pip.exe"
    "$pip" install --upgrade pip >/dev/null
    "$pip" install "pyarmor==${pyarmor_ver}" >/dev/null
}

bake_v7_super() {
    local venv="${VENV_ROOT}/pyarmor-7.7.4"
    local out="${OUT_ROOT}/v7-super"
    log_plan "v7-super -> $out"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    new_pyvenv "$venv" "7.7.4"
    local pyarmor="${venv}/bin/pyarmor"
    [[ -x "$pyarmor" ]] || pyarmor="${venv}/Scripts/pyarmor.exe"
    if [[ ! -x "$pyarmor" ]]; then
        log_skip "pyarmor-7.7.4 venv missing pyarmor entrypoint; skipping v7-super bake"
        return 0
    fi
    local stage; stage="$(mktemp -d -t disrobe-bake-v7-super-XXXXXX)"
    local src="${stage}/hello_v7_super.py"
    cat >"$src" <<'EOF'
def greet(name: str) -> str:
    return f"hello {name}"

if __name__ == "__main__":
    print(greet("world"))
EOF
    pushd "$stage" >/dev/null
    "$pyarmor" obfuscate --advanced 2 --output "$out" "$src"
    popd >/dev/null
    log_ok "v7-super baked into $out"
}

bake_v9_bcc() {
    local venv="${VENV_ROOT}/pyarmor-9.0.0"
    local out="${OUT_ROOT}/v9-bcc"
    log_plan "v9-bcc -> $out"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    new_pyvenv "$venv" "9.0.0"
    local pyarmor="${venv}/bin/pyarmor"
    [[ -x "$pyarmor" ]] || pyarmor="${venv}/Scripts/pyarmor.exe"
    if [[ ! -x "$pyarmor" ]]; then
        log_skip "pyarmor-9.0.0 venv missing pyarmor entrypoint; skipping v9-bcc bake"
        return 0
    fi
    local stage; stage="$(mktemp -d -t disrobe-bake-v9-bcc-XXXXXX)"
    local src="${stage}/hello_v9_bcc.py"
    cat >"$src" <<'EOF'
def fib(n: int) -> int:
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)

if __name__ == "__main__":
    print(fib(10))
EOF
    pushd "$stage" >/dev/null
    "$pyarmor" cfg bcc_mode=1 || true
    "$pyarmor" gen --enable-bcc --output "$out" "$src"
    popd >/dev/null
    log_ok "v9-bcc baked into $out"
}

stage_runtimes() {
    local rt_root="${OUT_ROOT}/_pytransform-runtimes"
    log_plan "stage _pytransform runtimes -> $rt_root"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    mkdir -p "$rt_root"
    for pair in "pyarmor-7.7.4:v7" "pyarmor-9.0.0:v9"; do
        local venv_name="${pair%%:*}"
        local tag="${pair##*:}"
        local venv="${VENV_ROOT}/${venv_name}"
        [[ -d "$venv" ]] || continue
        while IFS= read -r -d '' f; do
            local base; base="$(basename "$f")"
            cp -f "$f" "${rt_root}/${tag}_${base}"
            log_ok "staged $f -> ${rt_root}/${tag}_${base}"
        done < <(find "$venv" -type f \( -name '_pytransform*' -o -name 'pytransform*' \) -print0 2>/dev/null)
    done
}

mkdir -p "$OUT_ROOT"
log_plan "OutRoot=$OUT_ROOT"
bake_v7_super
bake_v9_bcc
stage_runtimes
log_ok "pyarmor bake complete"
