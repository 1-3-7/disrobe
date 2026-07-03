from __future__ import annotations

import json
import sys
from pathlib import Path


def normalize_code(code: object, /) -> object:
    return {
        "co_names": sorted(getattr(code, "co_names", ())),
        "co_varnames": list(getattr(code, "co_varnames", ())),
        "co_consts": [
            normalize_code(child) if hasattr(child, "co_code") else repr(child)
            for child in getattr(code, "co_consts", ())
        ],
        "co_argcount": getattr(code, "co_argcount", 0),
        "co_kwonlyargcount": getattr(code, "co_kwonlyargcount", 0),
        "names": sorted(
            getattr(child, "co_name", "")
            for child in getattr(code, "co_consts", ())
            if hasattr(child, "co_code")
        ),
    }


def grade(original_path: str, recovered_path: str, /) -> dict[str, object]:
    original_src: str = Path(original_path).read_text(encoding="utf-8")
    recovered_src: str = Path(recovered_path).read_text(encoding="utf-8")
    try:
        orig_code: object = compile(original_src, "<orig>", "exec")
    except SyntaxError as exc:
        return {"equivalent": False, "reason": f"original failed to compile: {exc}"}
    try:
        rec_code: object = compile(recovered_src, "<rec>", "exec")
    except SyntaxError as exc:
        return {"equivalent": False, "reason": f"recovered failed to compile: {exc}"}
    orig_norm: object = normalize_code(orig_code)
    rec_norm: object = normalize_code(rec_code)
    return {"equivalent": orig_norm == rec_norm, "orig": orig_norm, "rec": rec_norm}


def main(argv: list[str], /) -> int:
    verdict: dict[str, object] = grade(argv[1], argv[2])
    print(json.dumps(verdict))
    return 0 if verdict.get("equivalent") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
