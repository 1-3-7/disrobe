#!/usr/bin/env python3
from __future__ import annotations

import builtins
import gc
import hashlib
import importlib.util
import json
import marshal
import os
import pathlib
import runpy
import struct
import sys
import traceback
import types

_DISABLE_PYTRACE = os.environ.get("DISROBE_DISABLE_PYTRACE") == "1"
_DISABLE_CEXTRACT = os.environ.get("DISROBE_DISABLE_CEXTRACT") == "1"

if _DISABLE_PYTRACE:
    _PYTRACE_OK = False
    _PYTRACE_ERR: str | None = "disabled via DISROBE_DISABLE_PYTRACE"
    _native_pytrace = None
else:
    try:
        import disrobe_pytrace as _native_pytrace
        _PYTRACE_OK = True
        _PYTRACE_ERR = None
    except ImportError as _pytrace_import_error:
        _PYTRACE_OK = False
        _PYTRACE_ERR = f"{type(_pytrace_import_error).__name__}: {_pytrace_import_error}"
        _native_pytrace = None

if _DISABLE_CEXTRACT:
    _CEXTRACT_OK = False
    _CEXTRACT_ERR: str | None = "disabled via DISROBE_DISABLE_CEXTRACT"
    _native_cextract = None
else:
    try:
        import disrobe_cextract as _native_cextract
        _CEXTRACT_OK = True
        _CEXTRACT_ERR = None
    except ImportError as _cextract_import_error:
        _CEXTRACT_OK = False
        _CEXTRACT_ERR = f"{type(_cextract_import_error).__name__}: {_cextract_import_error}"
        _native_cextract = None


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: v6v7_dynamic_hook.py <wrapper> <out_dir>", file=sys.stderr)
        return 2

    wrapper_path = pathlib.Path(sys.argv[1]).resolve()
    out_dir = pathlib.Path(sys.argv[2]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not wrapper_path.is_file():
        print(f"wrapper not found: {wrapper_path}", file=sys.stderr)
        return 3

    captures_mp: list[bytes] = []
    captures_ah: list[bytes] = []
    captures_ex: list[bytes] = []
    captures_co: list[bytes] = []
    captures_tr: list[bytes] = []
    captures_gc: list[bytes] = []
    captures_pt: list[bytes] = []
    cextract_pyc_paths: list[dict[str, object]] = []
    seen_trace_codes: set[int] = set()
    exceptions: list[dict[str, object]] = []
    pytrace_installed = False
    cextract_installed = False
    cextract_backend = "none"

    if not _PYTRACE_OK and _PYTRACE_ERR is not None:
        exceptions.append({
            "phase": "pytrace-import",
            "type": "ImportError",
            "message": _PYTRACE_ERR,
        })
    if not _CEXTRACT_OK and _CEXTRACT_ERR is not None:
        exceptions.append({
            "phase": "cextract-import",
            "type": "ImportError",
            "message": _CEXTRACT_ERR,
        })

    def safe_marshal(obj) -> bytes | None:
        try:
            return marshal.dumps(obj)
        except Exception as e:
            exceptions.append({
                "phase": "marshal-dump",
                "type": type(e).__name__,
                "message": str(e),
            })
            return None

    original_loads = marshal.loads

    def patched_loads(data, *args, **kwargs):
        try:
            captures_mp.append(bytes(data))
        except Exception as e:
            exceptions.append({
                "phase": "capture-monkey",
                "type": type(e).__name__,
                "message": str(e),
            })
        return original_loads(data, *args, **kwargs)

    marshal.loads = patched_loads

    def audit_hook(event, args):
        if event == "marshal.loads" and args:
            try:
                captures_ah.append(bytes(args[0]))
            except Exception:
                pass

    sys.addaudithook(audit_hook)

    original_exec = builtins.exec

    def patched_exec(source, globals=None, locals=None):  # noqa: A002
        if isinstance(source, type((lambda: 0).__code__)):
            blob = safe_marshal(source)
            if blob is not None:
                captures_ex.append(blob)
        return original_exec(source, globals, locals)

    builtins.exec = patched_exec

    original_compile = builtins.compile

    def patched_compile(source, filename, mode, *args, **kwargs):
        result = original_compile(source, filename, mode, *args, **kwargs)
        if isinstance(result, type((lambda: 0).__code__)):
            blob = safe_marshal(result)
            if blob is not None:
                captures_co.append(blob)
        return result

    builtins.compile = patched_compile

    def trace_call(frame, event, arg):
        if event != "call":
            return None
        co = frame.f_code
        co_id = id(co)
        if co_id in seen_trace_codes:
            return None
        seen_trace_codes.add(co_id)
        co_file = co.co_filename or ""
        if any(seg in co_file for seg in ("\\lib\\", "/lib/", "site-packages", "\\runpy.py", "/runpy.py")):
            return None
        if co.co_name in {"<frozen importlib._bootstrap>", "_call_with_frames_removed"}:
            return None
        blob = safe_marshal(co)
        if blob is not None:
            captures_tr.append(blob)
        return None

    sys.settrace(trace_call)

    if _PYTRACE_OK and _native_pytrace is not None:
        try:
            pytrace_installed = bool(_native_pytrace.hook_into())
        except Exception as e:
            exceptions.append({
                "phase": "pytrace-hook",
                "type": type(e).__name__,
                "message": str(e),
            })

    if _CEXTRACT_OK and _native_cextract is not None:
        try:
            cextract_dir = out_dir / "cextract"
            cextract_dir.mkdir(parents=True, exist_ok=True)
            cextract_backend = _native_cextract.install_intercept(
                str(cextract_dir),
                wrapper_path.stem,
                importlib.util.MAGIC_NUMBER,
                None,
            )
            cextract_installed = cextract_backend in ("modern", "legacy")
        except Exception as e:
            exceptions.append({
                "phase": "cextract-install",
                "type": type(e).__name__,
                "message": str(e),
            })

    wrapper_dir = wrapper_path.parent
    try:
        os.chdir(wrapper_dir)
        sys.path.insert(0, str(wrapper_dir))
    except Exception as e:
        exceptions.append({
            "phase": "chdir",
            "type": type(e).__name__,
            "message": str(e),
        })

    try:
        runpy.run_path(str(wrapper_path), run_name="__main__")
    except SystemExit:
        pass
    except BaseException as e:
        exceptions.append({
            "phase": "runpy",
            "type": type(e).__name__,
            "message": str(e),
            "traceback": traceback.format_exc(),
        })
    finally:
        sys.settrace(None)
        if pytrace_installed and _native_pytrace is not None:
            try:
                drained = _native_pytrace.drain()
                for blob in drained:
                    if isinstance(blob, (bytes, bytearray)):
                        captures_pt.append(bytes(blob))
            except Exception as e:
                exceptions.append({
                    "phase": "pytrace-drain",
                    "type": type(e).__name__,
                    "message": str(e),
                })
        if cextract_installed and _native_cextract is not None:
            try:
                _native_cextract.uninstall_intercept()
                manifest_entries = _native_cextract.drain_into_manifest()
                for entry in manifest_entries:
                    cextract_pyc_paths.append({
                        "pyc_path": str(entry.get("pyc_path", "")),
                        "size": int(entry.get("size", 0)),
                        "blake3": str(entry.get("blake3", "")),
                    })
            except Exception as e:
                exceptions.append({
                    "phase": "cextract-drain",
                    "type": type(e).__name__,
                    "message": str(e),
                })

    wrapper_canonical = str(wrapper_path).replace("\\", "/").lower()
    seen_gc: set[int] = set()
    for obj in gc.get_objects():
        if not isinstance(obj, types.CodeType):
            continue
        co_id = id(obj)
        if co_id in seen_gc:
            continue
        seen_gc.add(co_id)
        co_file = (obj.co_filename or "").replace("\\", "/").lower()
        if not co_file:
            continue
        if any(seg in co_file for seg in ("/lib/", "site-packages", "/runpy.py", "/importlib", "<frozen ")):
            continue
        if co_file != wrapper_canonical and not co_file.endswith(wrapper_path.name.lower()):
            if "_dynhook" in co_file or "v6v7_dynamic_hook" in co_file:
                continue
            if co_file not in {"<string>", "<frozen importlib._bootstrap>", "<exec>"}:
                continue
        blob = safe_marshal(obj)
        if blob is not None:
            captures_gc.append(blob)

    magic_number = importlib.util.MAGIC_NUMBER
    pyc_header = magic_number + b"\x00\x00\x00\x00" + struct.pack("<II", 0, 0)
    stem = wrapper_path.stem

    captures_meta: dict[str, list[dict[str, object]]] = {
        "monkeypatch": [],
        "audithook": [],
        "exec": [],
        "compile": [],
        "trace": [],
        "gcwalk": [],
        "pytrace": [],
        "cextract": [],
    }
    sources_iter = (
        ("monkeypatch", "mo", captures_mp),
        ("audithook", "au", captures_ah),
        ("exec", "ex", captures_ex),
        ("compile", "co", captures_co),
        ("trace", "tr", captures_tr),
        ("gcwalk", "gc", captures_gc),
        ("pytrace", "pt", captures_pt),
    )
    rich_channels = {"pytrace", "exec", "compile"}
    for source_name, prefix, captures in sources_iter:
        for i, body in enumerate(captures):
            sha = hashlib.sha256(body).hexdigest()
            pyc_path = out_dir / f"{stem}_{prefix}_{i}.pyc"
            try:
                pyc_path.write_bytes(pyc_header + body)
            except Exception as e:
                exceptions.append({
                    "phase": "write-pyc",
                    "type": type(e).__name__,
                    "message": str(e),
                })
                continue
            co_filename = ""
            co_name_field = ""
            co_names_count = 0
            if source_name in rich_channels:
                try:
                    co_obj = marshal.loads(body)
                    if isinstance(co_obj, types.CodeType):
                        co_filename = co_obj.co_filename or ""
                        co_name_field = co_obj.co_name or ""
                        co_names_count = len(co_obj.co_names)
                except Exception:
                    pass
            captures_meta[source_name].append({
                "index": i,
                "size": len(body),
                "sha256": sha,
                "pyc_path": str(pyc_path),
                "co_filename": co_filename,
                "co_name": co_name_field,
                "co_names_count": co_names_count,
            })

    for i, entry in enumerate(cextract_pyc_paths):
        try:
            pyc_path = pathlib.Path(str(entry["pyc_path"]))
            sha = hashlib.sha256(pyc_path.read_bytes()).hexdigest() if pyc_path.exists() else ""
        except Exception:
            sha = ""
        co_filename = ""
        co_name_field = ""
        co_names_count = 0
        try:
            if pyc_path.exists():
                co_obj = marshal.loads(pyc_path.read_bytes()[16:])
                if isinstance(co_obj, types.CodeType):
                    co_filename = co_obj.co_filename or ""
                    co_name_field = co_obj.co_name or ""
                    co_names_count = len(co_obj.co_names)
        except Exception:
            pass
        captures_meta["cextract"].append({
            "index": i,
            "size": int(entry.get("size", 0)),
            "sha256": sha,
            "pyc_path": str(entry.get("pyc_path", "")),
            "co_filename": co_filename,
            "co_name": co_name_field,
            "co_names_count": co_names_count,
        })

    primary = None
    if captures_meta["cextract"]:
        primary = "cextract"
    elif captures_meta["pytrace"]:
        primary = "pytrace"
    elif captures_gc:
        primary = "gcwalk"
    elif captures_tr:
        primary = "trace"
    elif captures_ex:
        primary = "exec"
    elif captures_co:
        primary = "compile"
    elif captures_mp:
        primary = "monkeypatch"
    elif captures_ah:
        primary = "audithook"

    limitations: list[dict[str, str]] = []
    pytrace_limitation_msg = (
        "disrobe-pyarmor-pytrace runs at the Python tracing layer (sys.settrace). "
        "It cannot observe code objects executed by PyArmor v6/v7 via direct C-level "
        "PyEval_EvalCode calls from the _pytransform runtime; for those cases the cextract "
        "channel is the primary capture path."
    )
    if _native_pytrace is not None and hasattr(_native_pytrace, "__limitation__"):
        try:
            native_msg = str(getattr(_native_pytrace, "__limitation__"))
            if native_msg:
                pytrace_limitation_msg = native_msg
        except Exception:
            pass
    limitations.append({
        "id": "v6v7-c-eval-gap-pytrace",
        "channel": "pytrace",
        "severity": "documented",
        "message": pytrace_limitation_msg,
    })

    cextract_limitation_msg = (
        "disrobe-pyarmor-cextract was not loaded (module import failed); falling back to "
        "the python-level pytrace channel."
    )
    if _native_cextract is not None and hasattr(_native_cextract, "__limitation__"):
        try:
            native_msg = str(getattr(_native_cextract, "__limitation__"))
            if native_msg:
                cextract_limitation_msg = native_msg
        except Exception:
            pass
    cextract_severity = "active" if cextract_installed else "absent"
    limitations.append({
        "id": "v6v7-c-eval-gap-cextract",
        "channel": f"cextract:{cextract_backend}",
        "severity": cextract_severity,
        "message": cextract_limitation_msg,
    })

    manifest = {
        "schema": "disrobe.pyarmor.v6v7-dynhook/v1",
        "wrapper": str(wrapper_path),
        "subprocess_python": list(sys.version_info[:3]),
        "magic_number_hex": magic_number.hex(),
        "captures": captures_meta,
        "exceptions": exceptions,
        "limitations": limitations,
        "primary": primary,
    }

    manifest_path = out_dir / "manifest.json"
    try:
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"failed to write manifest: {e}", file=sys.stderr)
        return 4

    json.dump(manifest, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
