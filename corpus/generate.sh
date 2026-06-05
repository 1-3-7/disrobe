#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/src"
OUT="${SCRIPT_DIR}/generated"

DRY_RUN=0
EDGE_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --edge-cases) EDGE_ONLY=1 ;;
        -h|--help)
            echo "usage: $(basename "$0") [--dry-run] [--edge-cases]"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

log_plan() { echo "[plan] $*"; }
log_run()  { echo "[run]  $*"; }
log_skip() { echo "[skip] $*"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

plan_python() {
    local out_dir="${OUT}/python"
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_plan "python: $f -> ${out_dir}/${name}.pyc"
        count=$((count + 1))
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
    echo "[summary] python: ${count} sources"
}

build_python() {
    local out_dir="${OUT}/python"
    if ! has_cmd python3 && ! has_cmd python; then
        log_skip "python: no python3/python on PATH"
        return 0
    fi
    local py
    if has_cmd python3; then py=python3; else py=python; fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_run "python: compiling $name"
        "$py" -m py_compile "$f"
        local pyc
        pyc="$(find "${SRC}/python/__pycache__" -name "${name}.cpython-*.pyc" 2>/dev/null | head -1 || true)"
        if [ -n "$pyc" ]; then
            cp "$pyc" "${out_dir}/${name}.pyc"
        fi
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
}

plan_javascript() {
    local out_dir="${OUT}/javascript"
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .js)"
        log_plan "javascript: $f -> ${out_dir}/${name}.min.js"
        count=$((count + 1))
    done < <(find "${SRC}/javascript" -maxdepth 1 -name '*.js' -print0 2>/dev/null || true)
    echo "[summary] javascript: ${count} sources"
}

build_javascript() {
    local out_dir="${OUT}/javascript"
    if ! has_cmd node; then
        log_skip "javascript: no node on PATH"
        return 0
    fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .js)"
        log_run "javascript: copying $name"
        cp "$f" "${out_dir}/${name}.js"
    done < <(find "${SRC}/javascript" -maxdepth 1 -name '*.js' -print0 2>/dev/null || true)
}

plan_typescript() {
    local out_dir="${OUT}/typescript"
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .ts)"
        log_plan "typescript: $f -> ${out_dir}/${name}.js"
        count=$((count + 1))
    done < <(find "${SRC}/typescript" -maxdepth 1 -name '*.ts' -print0 2>/dev/null || true)
    echo "[summary] typescript: ${count} sources"
}

build_typescript() {
    local out_dir="${OUT}/typescript"
    if ! has_cmd tsc; then
        log_skip "typescript: no tsc on PATH"
        return 0
    fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .ts)"
        log_run "typescript: compiling $name"
        tsc "$f" --strict --target ES2022 --module ES2022 --moduleResolution Bundler --outDir "$out_dir" || true
    done < <(find "${SRC}/typescript" -maxdepth 1 -name '*.ts' -print0 2>/dev/null || true)
}

plan_wasm() {
    local out_dir="${OUT}/wasm"
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .wat)"
        log_plan "wasm: $f -> ${out_dir}/${name}.wasm"
        count=$((count + 1))
    done < <(find "${SRC}/wasm/sources" -maxdepth 1 -name '*.wat' -print0 2>/dev/null || true)
    echo "[summary] wasm: ${count} sources"
}

build_wasm() {
    local out_dir="${OUT}/wasm"
    if ! has_cmd wat2wasm; then
        log_skip "wasm: no wat2wasm on PATH (install via wabt)"
        return 0
    fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .wat)"
        log_run "wasm: compiling $name"
        wat2wasm --enable-exceptions "$f" -o "${out_dir}/${name}.wasm"
    done < <(find "${SRC}/wasm/sources" -maxdepth 1 -name '*.wat' -print0 2>/dev/null || true)
}

plan_wasm_dwarf() {
    local out_dir="${OUT}/wasm"
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .c)"
        log_plan "wasm-dwarf: $f -> ${out_dir}/${name}.wasm"
        count=$((count + 1))
    done < <(find "${SRC}/wasm/sources" -maxdepth 1 -name '*.c' -print0 2>/dev/null || true)
    echo "[summary] wasm-dwarf: ${count} sources"
}

build_wasm_dwarf() {
    local out_dir="${OUT}/wasm"
    if ! has_cmd clang; then
        log_skip "wasm-dwarf: no clang on PATH"
        return 0
    fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .c)"
        log_run "wasm-dwarf: compiling $name with debug info"
        clang --target=wasm32 -g -O0 -nostdlib -Wl,--no-entry -Wl,--export-all \
            -o "${out_dir}/${name}.wasm" "$f" \
            || log_skip "wasm-dwarf: failed on $name"
    done < <(find "${SRC}/wasm/sources" -maxdepth 1 -name '*.c' -print0 2>/dev/null || true)
}

plan_pyarmor() {
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_plan "pyarmor: ${f} -> .developer/pyarmor-build/${name}/dist/${name}.py"
        count=$((count + 1))
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
    echo "[summary] pyarmor: ${count} sources"
}

build_pyarmor() {
    if ! has_cmd pyarmor; then
        log_skip "pyarmor: pyarmor not on PATH"
        return 0
    fi
    local build_root="${SCRIPT_DIR}/../.developer/pyarmor-build"
    mkdir -p "$build_root"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_run "pyarmor: protecting $name"
        pyarmor gen --output "${build_root}/${name}" "$f" || log_skip "pyarmor: failed on $name"
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
}

plan_pyinstaller() {
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_plan "pyinstaller: ${f} -> .developer/pyinst-build/dist/${name}.exe"
        count=$((count + 1))
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
    echo "[summary] pyinstaller: ${count} sources"
}

build_pyinstaller() {
    if ! has_cmd pyinstaller; then
        log_skip "pyinstaller: pyinstaller not on PATH"
        return 0
    fi
    local build_root="${SCRIPT_DIR}/../.developer/pyinst-build"
    mkdir -p "$build_root"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_run "pyinstaller: building $name"
        pyinstaller --onefile --distpath "${build_root}/dist" --workpath "${build_root}/build" --specpath "$build_root" "$f" || log_skip "pyinstaller: failed on $name"
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
}

plan_nuitka() {
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_plan "nuitka: ${f} -> .developer/nuitka-build/${name}.dist/${name}.exe"
        count=$((count + 1))
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
    echo "[summary] nuitka: ${count} sources"
}

build_nuitka() {
    if ! has_cmd nuitka; then
        log_skip "nuitka: nuitka not on PATH"
        return 0
    fi
    local build_root="${SCRIPT_DIR}/../.developer/nuitka-build"
    mkdir -p "$build_root"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_run "nuitka: building $name"
        nuitka --standalone --output-dir="$build_root" "$f" || log_skip "nuitka: failed on $name"
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
}

plan_sourcedefender() {
    local count=0
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_plan "sourcedefender: ${f} -> .developer/sourcedefender-build/${name}.pye"
        count=$((count + 1))
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
    echo "[summary] sourcedefender: ${count} sources"
}

build_sourcedefender() {
    if ! has_cmd sourcedefender; then
        log_skip "sourcedefender: sourcedefender not on PATH"
        return 0
    fi
    local build_root="${SCRIPT_DIR}/../.developer/sourcedefender-build"
    mkdir -p "$build_root"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_run "sourcedefender: encrypting $name"
        sourcedefender encrypt --output "$build_root" "$f" || log_skip "sourcedefender: failed on $name"
    done < <(find "${SRC}/python" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
}

plan_edge_python() {
    local out_dir="${OUT}/python-edge"
    local dir="${SRC}/python/edge_cases"
    local count=0
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' f; do
            local name
            name="$(basename "$f" .py)"
            log_plan "python-edge: $f -> ${out_dir}/${name}.pyc"
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
    fi
    echo "[summary] python-edge: ${count} sources"
}

build_edge_python() {
    local out_dir="${OUT}/python-edge"
    local dir="${SRC}/python/edge_cases"
    if [ ! -d "$dir" ]; then return 0; fi
    if ! has_cmd python3 && ! has_cmd python; then
        log_skip "python-edge: no python3/python on PATH"
        return 0
    fi
    local py
    if has_cmd python3; then py=python3; else py=python; fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .py)"
        log_run "python-edge: compiling $name"
        "$py" -m py_compile "$f" || log_skip "python-edge: failed on $name"
        local pyc
        pyc="$(find "$dir/__pycache__" -name "${name}.cpython-*.pyc" 2>/dev/null | head -1 || true)"
        if [ -n "$pyc" ]; then
            cp "$pyc" "${out_dir}/${name}.pyc"
        fi
    done < <(find "$dir" -maxdepth 1 -name '*.py' -print0 2>/dev/null || true)
}

plan_edge_javascript() {
    local out_dir="${OUT}/javascript-edge"
    local dir="${SRC}/javascript/edge_cases"
    local count=0
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' f; do
            local name
            name="$(basename "$f")"
            log_plan "javascript-edge: $f -> ${out_dir}/${name}"
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 \( -name '*.js' -o -name '*.mjs' \) -print0 2>/dev/null || true)
    fi
    echo "[summary] javascript-edge: ${count} sources"
}

build_edge_javascript() {
    local out_dir="${OUT}/javascript-edge"
    local dir="${SRC}/javascript/edge_cases"
    if [ ! -d "$dir" ]; then return 0; fi
    if ! has_cmd node; then
        log_skip "javascript-edge: no node on PATH"
        return 0
    fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f")"
        log_run "javascript-edge: validating $name"
        node --check "$f" || log_skip "javascript-edge: parse failed on $name"
        cp "$f" "${out_dir}/${name}"
    done < <(find "$dir" -maxdepth 1 \( -name '*.js' -o -name '*.mjs' \) -print0 2>/dev/null || true)
}

plan_edge_typescript() {
    local out_dir="${OUT}/typescript-edge"
    local dir="${SRC}/typescript/edge_cases"
    local count=0
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' f; do
            local name
            name="$(basename "$f" .ts)"
            log_plan "typescript-edge: $f -> ${out_dir}/${name}.js"
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 -name '*.ts' -print0 2>/dev/null || true)
    fi
    echo "[summary] typescript-edge: ${count} sources"
}

build_edge_typescript() {
    local out_dir="${OUT}/typescript-edge"
    local dir="${SRC}/typescript/edge_cases"
    if [ ! -d "$dir" ]; then return 0; fi
    if ! has_cmd tsc; then
        log_skip "typescript-edge: no tsc on PATH"
        return 0
    fi
    mkdir -p "$out_dir"
    tsc --noEmit --target ES2022 --module ES2022 --moduleResolution Bundler --skipLibCheck "$dir"/*.ts || log_skip "typescript-edge: tsc reported diagnostics"
}

plan_edge_wasm() {
    local out_dir="${OUT}/wasm-edge"
    local dir="${SRC}/wasm/edge_cases"
    local count=0
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' f; do
            local name
            name="$(basename "$f" .wat)"
            log_plan "wasm-edge: $f -> ${out_dir}/${name}.wasm"
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 -name '*.wat' -print0 2>/dev/null || true)
    fi
    echo "[summary] wasm-edge: ${count} sources"
}

build_edge_wasm() {
    local out_dir="${OUT}/wasm-edge"
    local dir="${SRC}/wasm/edge_cases"
    if [ ! -d "$dir" ]; then return 0; fi
    if ! has_cmd wat2wasm; then
        log_skip "wasm-edge: no wat2wasm on PATH (install via wabt)"
        return 0
    fi
    mkdir -p "$out_dir"
    while IFS= read -r -d '' f; do
        local name
        name="$(basename "$f" .wat)"
        log_run "wasm-edge: compiling $name"
        wat2wasm --enable-all "$f" -o "${out_dir}/${name}.wasm" || log_skip "wasm-edge: failed on $name"
    done < <(find "$dir" -maxdepth 1 -name '*.wat' -print0 2>/dev/null || true)
}

plan_edge_native() {
    local dir="${SRC}/native/edge_cases"
    local count=0
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' f; do
            log_plan "native-edge: $f"
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 \( -name '*.c' -o -name '*.cpp' -o -name '*.go' -o -name '*.rs' \) -print0 2>/dev/null || true)
    fi
    echo "[summary] native-edge: ${count} sources"
}

build_edge_native() {
    local dir="${SRC}/native/edge_cases"
    if [ ! -d "$dir" ]; then return 0; fi
    while IFS= read -r -d '' recipe; do
        log_run "native-edge: ${recipe}"
        bash "$recipe" || log_skip "native-edge: failed ${recipe}"
    done < <(find "$dir" -maxdepth 1 -name '*.build.sh' -print0 2>/dev/null || true)
}

plan_edge_java() {
    local dir="${SRC}/java/edge_cases"
    local count=0
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' f; do
            log_plan "java-edge: $f"
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 -name '*.java' -print0 2>/dev/null || true)
    fi
    echo "[summary] java-edge: ${count} sources"
}

build_edge_java() {
    local out_dir="${OUT}/java-edge"
    local dir="${SRC}/java/edge_cases"
    if [ ! -d "$dir" ]; then return 0; fi
    if ! has_cmd javac; then
        log_skip "java-edge: no javac on PATH"
        return 0
    fi
    mkdir -p "$out_dir"
    javac -d "$out_dir" --release 21 "$dir"/*.java || log_skip "java-edge: javac failed"
}

plan_edge_lua() {
    local dir="${SRC}/lua/edge_cases"
    local count=0
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' f; do
            log_plan "lua-edge: $f"
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 -name '*.lua' -print0 2>/dev/null || true)
    fi
    echo "[summary] lua-edge: ${count} sources"
}

build_edge_lua() {
    local dir="${SRC}/lua/edge_cases"
    if [ ! -d "$dir" ]; then return 0; fi
    local lua_bin=""
    if has_cmd luac5.4; then lua_bin=luac5.4
    elif has_cmd luac; then lua_bin=luac
    else
        log_skip "lua-edge: no luac on PATH"
        return 0
    fi
    while IFS= read -r -d '' f; do
        log_run "lua-edge: parsing $f"
        "$lua_bin" -p "$f" >/dev/null 2>&1 || log_skip "lua-edge: parse failed on $f"
    done < <(find "$dir" -maxdepth 1 -name '*.lua' -print0 2>/dev/null || true)
}

if [ "$EDGE_ONLY" = 1 ]; then
    if [ "$DRY_RUN" = 1 ]; then
        plan_edge_python
        plan_edge_javascript
        plan_edge_typescript
        plan_edge_wasm
        plan_edge_native
        plan_edge_java
        plan_edge_lua
        echo "dry-run complete (edge-cases only; no compilers invoked)"
        exit 0
    fi
    mkdir -p "$OUT"
    build_edge_python
    build_edge_javascript
    build_edge_typescript
    build_edge_wasm
    build_edge_native
    build_edge_java
    build_edge_lua
    echo "edge-case corpus generation complete. output: $OUT"
    exit 0
fi

if [ "$DRY_RUN" = 1 ]; then
    plan_python
    plan_javascript
    plan_typescript
    plan_wasm
    plan_wasm_dwarf
    plan_pyarmor
    plan_pyinstaller
    plan_nuitka
    plan_sourcedefender
    plan_edge_python
    plan_edge_javascript
    plan_edge_typescript
    plan_edge_wasm
    plan_edge_native
    plan_edge_java
    plan_edge_lua
    echo "dry-run complete (no compilers invoked)"
    exit 0
fi

mkdir -p "$OUT"
build_python
build_javascript
build_typescript
build_wasm
build_wasm_dwarf
build_pyarmor
build_pyinstaller
build_nuitka
build_sourcedefender
build_edge_python
build_edge_javascript
build_edge_typescript
build_edge_wasm
build_edge_native
build_edge_java
build_edge_lua

echo "corpus generation complete. output: $OUT"
