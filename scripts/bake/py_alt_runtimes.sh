#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CORPUS_ROOT="${REPO_ROOT}/corpus/python/alt_runtimes"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help)
            echo "usage: $(basename "$0") [--dry-run]"
            echo "  bakes python alternative-runtime fixtures (PyPy, MicroPython, Jython, IronPython, Brython)"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

has_cmd() { command -v "$1" >/dev/null 2>&1; }
log_plan() { echo "[plan]    $*"; }
log_run()  { echo "[run]     $*"; }
log_skip() { echo "[skip]    $*"; }
log_done() { echo "[done]    $*"; }

bake_pypy() {
    local out_dir="${CORPUS_ROOT}/pypy"
    mkdir -p "${out_dir}"
    cat > "${out_dir}/hello.py" <<'PY'
def greet(name):
    return f"hello, {name}"


print(greet("pypy"))
PY
    log_plan "pypy: compile hello.py with pypy3 -> hello.pypy3.pyc"
    if [ "${DRY_RUN}" = "1" ]; then return 0; fi
    if ! has_cmd pypy3; then
        log_skip "pypy: pypy3 not on PATH (try: apt install pypy3 / brew install pypy3)"
        return 0
    fi
    log_run "pypy: compiling"
    (cd "${out_dir}" && pypy3 -c "import py_compile; py_compile.compile('hello.py', 'hello.pypy3.pyc')")
    log_done "pypy: ${out_dir}/hello.pypy3.pyc"
}

bake_micropython_bytecode() {
    local out_dir="${CORPUS_ROOT}/micropython"
    mkdir -p "${out_dir}"
    cat > "${out_dir}/hello.py" <<'PY'
def add(a, b):
    return a + b


print(add(1, 2))
PY
    log_plan "micropython: mpy-cross hello.py -> hello.mpy"
    if [ "${DRY_RUN}" = "1" ]; then return 0; fi
    if has_cmd mpy-cross; then
        log_run "micropython: mpy-cross"
        (cd "${out_dir}" && mpy-cross hello.py -o hello.mpy)
        log_done "micropython: ${out_dir}/hello.mpy"
    elif has_cmd docker; then
        log_run "micropython: docker run micropython/unix mpy-cross"
        docker run --rm -v "${out_dir}:/src" -w /src micropython/unix mpy-cross hello.py -o hello.mpy || \
            log_skip "micropython: docker image missing"
    else
        log_skip "micropython: neither mpy-cross nor docker available"
    fi
}

bake_micropython_native() {
    local out_dir="${CORPUS_ROOT}/micropython"
    mkdir -p "${out_dir}"
    log_plan "micropython-native: mpy-cross -X emit=native hello.py -> hello.native.mpy"
    if [ "${DRY_RUN}" = "1" ]; then return 0; fi
    if has_cmd mpy-cross; then
        log_run "micropython-native: mpy-cross emit=native"
        (cd "${out_dir}" && mpy-cross -X emit=native hello.py -o hello.native.mpy) || \
            log_skip "micropython-native: emit=native failed (arch unsupported on host)"
    else
        log_skip "micropython-native: mpy-cross not available"
    fi
}

bake_jython() {
    local out_dir="${CORPUS_ROOT}/jython"
    mkdir -p "${out_dir}"
    cat > "${out_dir}/hello.py" <<'PY'
def greet():
    return 'hi from jython'


if __name__ == '__main__':
    print(greet())
PY
    log_plan "jython: compile hello.py -> hello\$py.class"
    if [ "${DRY_RUN}" = "1" ]; then return 0; fi
    if has_cmd jython; then
        log_run "jython: compile"
        (cd "${out_dir}" && jython -c "from compileall import compile_file; compile_file('hello.py')")
        log_done "jython: ${out_dir}/hello\$py.class"
    elif has_cmd docker; then
        log_run "jython: docker run jython:2.7"
        docker run --rm -v "${out_dir}:/src" -w /src jython:2.7 \
            jython -c "from compileall import compile_file; compile_file('hello.py')" || \
            log_skip "jython: docker image missing"
    else
        log_skip "jython: neither jython nor docker available"
    fi
}

bake_ironpython() {
    local out_dir="${CORPUS_ROOT}/ironpython"
    mkdir -p "${out_dir}"
    cat > "${out_dir}/hello.py" <<'PY'
def greet():
    return 'hi from ironpython'


if __name__ == '__main__':
    print(greet())
PY
    log_plan "ironpython: ipy hello.py -> hello.dll (when ipyc available)"
    if [ "${DRY_RUN}" = "1" ]; then return 0; fi
    if has_cmd ipy; then
        log_run "ironpython: ipy compile"
        (cd "${out_dir}" && ipy -c "import clr; clr.CompileModules('hello.dll', 'hello.py')") || \
            log_skip "ironpython: compile failed"
    else
        log_skip "ironpython: ipy not on PATH (install IronPython release)"
    fi
}

bake_brython() {
    local out_dir="${CORPUS_ROOT}/brython"
    mkdir -p "${out_dir}"
    cat > "${out_dir}/hello.py" <<'PY'
def greet():
    return 'hi from brython'


print(greet())
PY
    cat > "${out_dir}/hello.brython.js" <<'JS'
;(function() {
    var $B = __BRYTHON__;
    $B.imported['hello'] = (function() {
        var $locals_hello = {};
        $locals_hello.greet = function() { return 'hi from brython'; };
        $B.modules['hello'] = $locals_hello;
        return $locals_hello;
    })();
})();
JS
    log_plan "brython: emit synthetic hello.brython.js (hand-shape; npm brython optional)"
    if [ "${DRY_RUN}" = "1" ]; then return 0; fi
    if has_cmd npx; then
        log_run "brython: npx brython-cli (best effort)"
        (cd "${out_dir}" && npx --yes brython-cli@latest --modules hello.py >/dev/null 2>&1) || \
            log_skip "brython: brython-cli not available (using hand-shaped fixture)"
    else
        log_skip "brython: npx not available (using hand-shaped fixture)"
    fi
    log_done "brython: ${out_dir}/hello.brython.js"
}

main() {
    mkdir -p "${CORPUS_ROOT}"
    bake_pypy
    bake_micropython_bytecode
    bake_micropython_native
    bake_jython
    bake_ironpython
    bake_brython
    echo
    echo "[summary] alt-runtime fixtures baked under ${CORPUS_ROOT}"
}

main
