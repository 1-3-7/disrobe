from __future__ import annotations

import ctypes
import importlib.util
import json
import marshal
import os
import pathlib
import sys
import tempfile
import types


def call_eval_code_via_c(code_obj: types.CodeType) -> dict[str, object]:
    pyapi = ctypes.pythonapi
    pyapi.PyEval_EvalCode.argtypes = [ctypes.py_object, ctypes.py_object, ctypes.py_object]
    pyapi.PyEval_EvalCode.restype = ctypes.py_object
    g: dict[str, object] = {"__name__": "__c_eval__"}
    pyapi.PyEval_EvalCode(code_obj, g, g)
    return g


def main() -> int:
    import disrobe_cextract as cx

    out_dir = pathlib.Path(tempfile.mkdtemp(prefix="disrobe_cextract_e2e_"))
    magic = importlib.util.MAGIC_NUMBER
    backend_name = cx.install_intercept(str(out_dir), "ceval_user", magic, None)
    print(f"backend: {backend_name}", flush=True)

    src = "X_CEVAL_SENTINEL = 0xDEADBEEF\n"
    user_code = compile(src, "ceval_user.py", "exec")

    g = call_eval_code_via_c(user_code)
    assert g.get("X_CEVAL_SENTINEL") == 0xDEADBEEF, "PyEval_EvalCode did not execute the user code"

    captured = cx.uninstall_intercept()
    print(f"captured count: {captured}", flush=True)

    drained = cx.drain_into_manifest()
    print(f"drained entries: {len(drained)}", flush=True)

    pyc_paths = [str(e["pyc_path"]) for e in drained]
    found = False
    target_sentinel = "X_CEVAL_SENTINEL"
    for p in pyc_paths:
        body = pathlib.Path(p).read_bytes()
        if len(body) <= 16:
            continue
        try:
            co = marshal.loads(body[16:])
        except Exception:
            continue
        if not isinstance(co, types.CodeType):
            continue
        if co.co_filename == "ceval_user.py" and target_sentinel in co.co_names:
            found = True
            break

    result = {
        "backend": backend_name,
        "captured": captured,
        "drained": len(drained),
        "matched_user_code": found,
        "pyc_paths": pyc_paths,
    }
    print(json.dumps(result, indent=2))
    if not found:
        print("FAIL: user-code object was not captured via the C-eval intercept", file=sys.stderr)
        return 1
    print("OK: user-code captured via cextract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
