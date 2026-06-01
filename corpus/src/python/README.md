# Python playground

Hand-authored Python sources fed through disrobe's Python-side passes (`disrobe-pass-py-disasm`, `disrobe-pass-py-deob`, `disrobe-pass-pyarmor`, `disrobe-pass-pyinstaller`, `disrobe-pass-nuitka`, `disrobe-pass-sourcedefender`).

| file | target | how to feed disrobe |
|------|--------|---------------------|
| `hello.py` | minimal ground-truth, smoke test bytecode round-trip | `python -m py_compile hello.py && disrobe py decompile __pycache__/hello.cpython-*.pyc` |
| `playground-small.py` | reduced opcode surface, fast iteration during pass dev | `python -m py_compile playground-small.py && disrobe py decompile __pycache__/playground-small.cpython-*.pyc` |
| `playground-mid.py` | mid-size opcode surface, control-flow + closures | `python -m py_compile playground-mid.py && disrobe py decompile __pycache__/playground-mid.cpython-*.pyc` |
| `playground.py` | maximum opcode coverage (async, match, generics, dataclass, descriptors, metaclass, EH groups) | wrap with PyArmor / PyInstaller / Nuitka in `.developer/` then `disrobe pyarmor unpack <build>`, `disrobe pyinstaller extract <exe>`, `disrobe nuitka decompile <build>` |

Same sources are wrapped by the four bundler/protector directories (`../pyarmor/`, `../pyinstaller/`, `../nuitka/`, `../sourcedefender/`) which document the build invocation; built artifacts land in `.developer/` (out-of-tree).
