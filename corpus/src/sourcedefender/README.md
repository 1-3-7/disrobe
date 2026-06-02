# SourceDefender wrappers

SourceDefender target sources live in `../python/`; `.pye` envelopes are built out-of-tree in `.developer/sourcedefender-build/` so that encrypted blobs do not pollute `corpus/`.

| target source | invocation | output |
|--------------|------------|--------|
| `../python/hello.py` | `sourcedefender encrypt --output .developer/sourcedefender-build ../python/hello.py` | `.developer/sourcedefender-build/hello.pye` |
| `../python/playground-small.py` | same with `playground-small.py` | `.developer/sourcedefender-build/playground-small.pye` |
| `../python/playground-mid.py` | same with `playground-mid.py` | `.developer/sourcedefender-build/playground-mid.pye` |
| `../python/playground.py` | same with `playground.py` | `.developer/sourcedefender-build/playground.pye` |

Feed into disrobe via `disrobe sourcedefender decrypt .developer/sourcedefender-build/<name>.pye`. `corpus/generate.{sh,ps1}` skips this stage if `sourcedefender` is not on PATH.
