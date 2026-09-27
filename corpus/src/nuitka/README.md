# Nuitka wrappers

Nuitka target sources live in `../python/`; Nuitka builds run out-of-tree in `.fixture-build/nuitka-build/` so that compiled `.dist/` directories & intermediate `.c`/`.o` files do not pollute `corpus/`.

| target source | invocation | output |
|--------------|------------|--------|
| `../python/hello.py` | `nuitka --standalone --output-dir=.fixture-build/nuitka-build ../python/hello.py` | `.fixture-build/nuitka-build/hello.dist/hello.exe` |
| `../python/playground-small.py` | same with `playground-small.py` | `.fixture-build/nuitka-build/playground-small.dist/playground-small.exe` |
| `../python/playground-mid.py` | same with `playground-mid.py` | `.fixture-build/nuitka-build/playground-mid.dist/playground-mid.exe` |
| `../python/playground.py` | same with `playground.py` | `.fixture-build/nuitka-build/playground.dist/playground.exe` |

Feed into disrobe via `disrobe nuitka decompile .fixture-build/nuitka-build/<name>.dist/<name>.exe`. `corpus/generate.{sh,ps1}` skips this stage if `nuitka` is not on PATH.
