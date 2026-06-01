from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile


def main() -> int:
    os.environ["DISROBE_CEXTRACT_BACKEND"] = "hotpatch"
    import disrobe_cextract as cx

    out_dir = pathlib.Path(tempfile.mkdtemp(prefix="disrobe_envvar_backend_"))
    magic = importlib.util.MAGIC_NUMBER
    backend_name = cx.install_intercept(str(out_dir), "envvar", magic, None)
    info = cx.backend_info()
    print(json.dumps({"selected": backend_name, "current": info.get("current")}, indent=2))
    if backend_name != "hotpatch":
        print(f"FAIL: env var was 'hotpatch' but selected '{backend_name}'", file=sys.stderr)
        cx.uninstall_intercept()
        return 1
    if info.get("current") != "hotpatch":
        print(f"FAIL: backend_info reports '{info.get('current')}' not 'hotpatch'", file=sys.stderr)
        cx.uninstall_intercept()
        return 1
    cx.uninstall_intercept()
    print("OK: env var override respected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
