# SourceDefender wrappers

SourceDefender target sources live in `../python/`; `.pye` envelopes are built out-of-tree in `.fixture-build/sourcedefender-build/` so that encrypted blobs do not pollute `corpus/`.

| target source | invocation | output |
|--------------|------------|--------|
| `../python/hello.py` | `sourcedefender encrypt --output .fixture-build/sourcedefender-build ../python/hello.py` | `.fixture-build/sourcedefender-build/hello.pye` |
| `../python/playground-small.py` | same with `playground-small.py` | `.fixture-build/sourcedefender-build/playground-small.pye` |
| `../python/playground-mid.py` | same with `playground-mid.py` | `.fixture-build/sourcedefender-build/playground-mid.pye` |
| `../python/playground.py` | same with `playground.py` | `.fixture-build/sourcedefender-build/playground.pye` |

Feed into disrobe via `disrobe sourcedefender decrypt .fixture-build/sourcedefender-build/<name>.pye`. `corpus/generate.{sh,ps1}` skips this stage if `sourcedefender` is not on PATH.
