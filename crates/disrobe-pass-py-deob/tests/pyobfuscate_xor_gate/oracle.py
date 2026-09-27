from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def reparses(path: Path, /) -> bool:
    source: str = path.read_text(encoding="utf-8")
    try:
        compile(source, str(path), "exec")
    except SyntaxError:
        return False
    return True


def run_capture(path: Path, /) -> tuple[int, str]:
    proc: subprocess.CompletedProcess[str] = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return proc.returncode, proc.stdout


def main(argv: list[str], /) -> int:
    mode: str = argv[1]
    if mode == "reparse":
        target: Path = Path(argv[2])
        print("OK" if reparses(target) else "FAIL")
        return 0
    if mode == "equivalent":
        recovered: Path = Path(argv[2])
        expected_rc: int = int(argv[3])
        expected_out: str = Path(argv[4]).read_text(encoding="utf-8")
        if not reparses(recovered):
            print("RECOVERED_PARSE_FAIL")
            return 0
        rc_r, out_r = run_capture(recovered)
        equivalent: bool = rc_r == expected_rc and out_r == expected_out
        print("EQUIVALENT" if equivalent else "MISMATCH")
        if not equivalent:
            print(f"pinned rc={expected_rc} stdout={expected_out!r}", file=sys.stderr)
            print(f"recovered rc={rc_r} stdout={out_r!r}", file=sys.stderr)
        return 0
    print(f"unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
