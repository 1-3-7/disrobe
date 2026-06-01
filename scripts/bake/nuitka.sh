#!/usr/bin/env bash
set -euo pipefail

NUITKA_VERSION="${NUITKA_VERSION:-4.1.1}"
DRY_RUN="${DRY_RUN:-0}"
FORCE="${FORCE:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CORPUS_ROOT="$REPO_ROOT/corpus/python/nuitka"
VENV_DIR="$REPO_ROOT/.developer/nuitka-venv"
BUILD_ROOT="$REPO_ROOT/.developer/nuitka-bake"
HELLO_PY="$BUILD_ROOT/hello.py"

log_plan() { printf '[plan] %s\n' "$*"; }
log_step() { printf '[step] %s\n' "$*"; }
log_skip() { printf '[skip] %s\n' "$*"; }
log_done() { printf '[done] %s\n' "$*"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

pick_py() {
    if has_cmd python3; then printf '%s' python3; return; fi
    if has_cmd python; then printf '%s' python; return; fi
    printf ''
}

ensure_venv() {
    local py
    py="$(pick_py)"
    if [[ -z "$py" ]]; then echo "python not on PATH" >&2; exit 1; fi
    if [[ -d "$VENV_DIR" ]]; then
        if [[ "$FORCE" != "1" ]]; then log_skip "venv exists: $VENV_DIR"; return; fi
        rm -rf "$VENV_DIR"
    fi
    log_step "creating venv -> $VENV_DIR"
    "$py" -m venv --without-pip "$VENV_DIR"
    local vpy
    vpy="$(venv_py)"
    "$vpy" -m ensurepip --upgrade
}

venv_py() {
    if [[ -x "$VENV_DIR/bin/python" ]]; then
        printf '%s' "$VENV_DIR/bin/python"
    elif [[ -x "$VENV_DIR/Scripts/python.exe" ]]; then
        printf '%s' "$VENV_DIR/Scripts/python.exe"
    else
        echo "no venv python at $VENV_DIR" >&2; exit 1
    fi
}

ensure_nuitka() {
    local vpy
    vpy="$(venv_py)"
    log_step "installing nuitka==$NUITKA_VERSION + zstandard + ordered-set"
    "$vpy" -m pip install --quiet --upgrade pip
    "$vpy" -m pip install --quiet "nuitka==$NUITKA_VERSION" zstandard ordered-set
}

write_hello() {
    mkdir -p "$BUILD_ROOT"
    cat > "$HELLO_PY" <<'PY'
def greet(name: str) -> str:
    return f"hello, {name}"

def fib(n: int) -> int:
    if n < 2:
        return n
    a, b = 0, 1
    for _ in range(n - 1):
        a, b = b, a + b
    return b

def main() -> int:
    print(greet("disrobe"))
    print(fib(20))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
PY
}

invoke_variant() {
    local name="$1"; shift
    local extra_args=("$@")
    local out_dir="$CORPUS_ROOT/$name"
    local stage_dir="$BUILD_ROOT/$name"
    if [[ -d "$out_dir" && "$FORCE" != "1" ]]; then
        log_skip "variant exists: $out_dir"
        return
    fi
    mkdir -p "$stage_dir"
    rm -rf "$out_dir"
    mkdir -p "$out_dir"
    local vpy
    vpy="$(venv_py)"
    log_step "nuitka [$name] -> $stage_dir"
    "$vpy" -m nuitka --assume-yes-for-downloads "--output-dir=$stage_dir" "${extra_args[@]}" "$HELLO_PY"
    (cd "$stage_dir" && find . -type f -print0 | while IFS= read -r -d '' f; do
        rel="${f#./}"
        dst="$out_dir/$rel"
        mkdir -p "$(dirname "$dst")"
        cp -f "$f" "$dst"
    done)
    log_done "variant baked: $out_dir"
}

plan() {
    log_plan "venv: $VENV_DIR (nuitka==$NUITKA_VERSION)"
    log_plan "hello.py: $HELLO_PY"
    log_plan "out root: $CORPUS_ROOT"
    for v in onefile standalone module static-libpython plugin-anti-bloat; do
        log_plan "variant: $v -> $CORPUS_ROOT/$v"
    done
    case "$(uname -s)" in
        Darwin) log_plan "variant: macos-bundle -> $CORPUS_ROOT/macos-bundle" ;;
        *) ;;
    esac
}

if [[ "$DRY_RUN" == "1" ]]; then plan; exit 0; fi

ensure_venv
ensure_nuitka
write_hello

try_variant() {
    local name="$1"; shift
    set +e
    ( set -e; invoke_variant "$name" "$@" )
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then log_skip "$name unavailable on this host (exit $rc)"; fi
}

try_variant onefile --onefile
try_variant standalone --standalone
try_variant module --module
try_variant static-libpython --standalone --static-libpython=yes
try_variant plugin-anti-bloat --standalone --enable-plugin=anti-bloat

case "$(uname -s)" in
    Darwin)
        try_variant macos-bundle --standalone --macos-create-app-bundle
        ;;
    *)
        log_skip "macos-bundle: macOS-only variant"
        ;;
esac

log_done "all variants baked under $CORPUS_ROOT"
