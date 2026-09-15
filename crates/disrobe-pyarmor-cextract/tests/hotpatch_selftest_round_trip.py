from __future__ import annotations

import json
import sys


def main() -> int:
    import disrobe_cextract as cx

    result = cx._hotpatch_selftest()
    print(json.dumps(result, indent=2))
    if not result.get("post_uninstall_eval_works"):
        print("FAIL: PyEval_EvalCode did not work after uninstall", file=sys.stderr)
        return 1
    if result.get("captured", 0) < 1:
        print("FAIL: hotpatch did not capture sentinel code", file=sys.stderr)
        return 1
    if result.get("sentinel_value") != 0xC0FFEE:
        print("FAIL: sentinel value mismatch", file=sys.stderr)
        return 1
    print("OK: hotpatch selftest round-trip succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
