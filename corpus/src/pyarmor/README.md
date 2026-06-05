# PyArmor wrappers

PyArmor target sources live in `../python/`; PyArmor itself runs out-of-tree in `.developer/pyarmor-build/` so that licensed runtime artifacts & pyarmor-runtime shared objects do not pollute `corpus/`.

## Supported versions & expected wrapper magic

| pyarmor version | wrapper magic | cipher | runtime layout | python window | disrobe support |
|----------------|---------------|--------|----------------|---------------|-----------------|
| v3 | `__pyarmor__(...)` + leading mode byte `0x01` | DES | `pytransform/_pytransform.{dll,so,dylib}` | 2.7 - 3.5 | detection only (no real-world sample corpus available) |
| v4 | `__pyarmor__(...)` + leading mode byte `0x02` | DES + AES mixed | `pytransform/_pytransform.{dll,so,dylib}` | 2.7 - 3.6 | detection only (no real-world sample corpus available) |
| v5 | `__pyarmor__(...)` + leading mode byte `0x05` | AES | `pytransform/_pytransform.{dll,so,dylib}` | 3.0 - 3.7 | detection only (no real-world sample corpus available) |
| v6 | `b"PYARMOR\0"` + pyver (2B) + pyc magic (4B) | AES-128-CTR, counter init = 2 | `pytransform/_pytransform.{dll,so,dylib}` | 3.0 - 3.7 | dynamic-hook fallback (static key extraction is the documented disrobe novel gap) |
| v6.2+ super | `pyarmor(...)` not `__pyarmor__(...)`, mode 1 | AES-128-CTR | single `pytransform.pyd` mutating `PyCode_Type` | 3.0 - 3.7 | dynamic-hook fallback |
| v7 | `b"PYARMOR\0"` + pyver (2B) + pyc magic (4B) | AES-128-CTR, counter init = 2 | `pytransform/_pytransform.{dll,so,dylib}` | 3.8 - 3.9 | dynamic-hook fallback |
| v8 | `b"PY008NNN"` (ASCII PY + 6-digit serial) | AES-128-GCM (CTR effective) | `pyarmor_runtime_NNNNNN/pyarmor_runtime.{pyd,so,dylib}` | 3.7 - 3.13 | pure-static unwrap (MD5-derived AES key) |
| v9 | `b"PY009NNN"` (ASCII PY + 6-digit serial) | AES-128-GCM (CTR effective) | `pyarmor_runtime_NNNNNN/pyarmor_runtime.{pyd,so,dylib}` | 3.7 - 3.14 | pure-static unwrap (MD5-derived AES key) |
| v9 BCC | header byte off 20 = `0x09` | nested AES blobs + clang-compiled C body | `pyarmor_runtime_NNNNNN/pyarmor_runtime.{pyd,so,dylib}` + native body | 3.7 - 3.14 | python half unwrapped; BCC body lift requires `--allow-bcc` + ghidra-headless on PATH |
| v9 Pro | stage-2 trailer bit `0x20` on top of v9 | stage-2 AES-CTR (bind-required when flag byte != 0x00/0xFF) | same as v9 | 3.7 - 3.14 | stage-2 parsed + bindless segments decrypted; hardware/license-bound segments surface in `nine_pro_stage_2_bind_required` |

## Generation recipes

| target source | invocation | output |
|--------------|------------|--------|
| `../python/hello.py` | `pyarmor gen --output .developer/pyarmor-build/hello ../python/hello.py` | `.developer/pyarmor-build/hello/dist/hello.py` (PyArmor v9 default) |
| `../python/playground-small.py` | `pyarmor gen --output .developer/pyarmor-build/small ../python/playground-small.py` | `.developer/pyarmor-build/small/dist/playground-small.py` |
| `../python/playground-mid.py` | `pyarmor gen --output .developer/pyarmor-build/mid ../python/playground-mid.py` | `.developer/pyarmor-build/mid/dist/playground-mid.py` |
| `../python/playground.py` | `pyarmor gen --output .developer/pyarmor-build/full ../python/playground.py` | `.developer/pyarmor-build/full/dist/playground.py` |

Feed into disrobe via `disrobe pyarmor unpack .developer/pyarmor-build/<name>/dist/<file>.py`. `corpus/generate.{sh,ps1}` skips this stage if `pyarmor` is not on PATH.

## Validator integration

`disrobe-validator` walks both `corpus/src/pyarmor/` (sources) & `corpus/generated/pyarmor/<version>/` (generated wrappers if present). The validator classifier (`crates/disrobe-validator/src/corpus.rs`) treats any path containing `/pyarmor` or version markers (`/v3-`, `/v4-`, `/v5-`, `/v6-`, `/v7-`, `/v8-`, `/v9-`) as a `CorpusKind::PyArmor` entry.
