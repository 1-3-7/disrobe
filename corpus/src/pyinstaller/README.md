# PyInstaller wrappers

PyInstaller target sources live in `../python/`; PyInstaller builds run out-of-tree in `.fixture-build/pyinst-build/` so that the heavyweight `dist/` & `build/` trees do not pollute `corpus/`.

| target source | invocation | output |
|--------------|------------|--------|
| `../python/hello.py` | `pyinstaller --onefile --distpath .fixture-build/pyinst-build/dist --workpath .fixture-build/pyinst-build/build --specpath .fixture-build/pyinst-build ../python/hello.py` | `.fixture-build/pyinst-build/dist/hello.exe` |
| `../python/playground-small.py` | same with `playground-small.py` | `.fixture-build/pyinst-build/dist/playground-small.exe` |
| `../python/playground-mid.py` | same with `playground-mid.py` | `.fixture-build/pyinst-build/dist/playground-mid.exe` |
| `../python/playground.py` | same with `playground.py` | `.fixture-build/pyinst-build/dist/playground.exe` |

Feed into disrobe via `disrobe pyinstaller extract .fixture-build/pyinst-build/dist/<name>.exe`. `corpus/generate.{sh,ps1}` skips this stage if `pyinstaller` is not on PATH.
