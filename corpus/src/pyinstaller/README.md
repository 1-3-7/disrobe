# PyInstaller wrappers

PyInstaller target sources live in `../python/`; PyInstaller builds run out-of-tree in `.developer/pyinst-build/` so that the heavyweight `dist/` and `build/` trees do not pollute `corpus/`.

| target source | invocation | output |
|--------------|------------|--------|
| `../python/hello.py` | `pyinstaller --onefile --distpath .developer/pyinst-build/dist --workpath .developer/pyinst-build/build --specpath .developer/pyinst-build ../python/hello.py` | `.developer/pyinst-build/dist/hello.exe` |
| `../python/playground-small.py` | same with `playground-small.py` | `.developer/pyinst-build/dist/playground-small.exe` |
| `../python/playground-mid.py` | same with `playground-mid.py` | `.developer/pyinst-build/dist/playground-mid.exe` |
| `../python/playground.py` | same with `playground.py` | `.developer/pyinst-build/dist/playground.exe` |

Feed into disrobe via `disrobe pyinstaller extract .developer/pyinst-build/dist/<name>.exe`. `corpus/generate.{sh,ps1}` skips this stage if `pyinstaller` is not on PATH.
