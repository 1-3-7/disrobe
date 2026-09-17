from __future__ import annotations

import sys
from pathlib import Path

SECTIONS: int = 65_300


def render() -> str:
    lines: list[str] = [".text", ".globl bigobj_large_probe", "bigobj_large_probe:", "  ret"]
    for index in range(SECTIONS):
        lines.append(f'.section s{index:05d},"dr"')
        lines.append(".byte 0")
    return "\n".join(lines) + "\n"


def main() -> int:
    destination: Path = Path(sys.argv[1] if len(sys.argv) > 1 else "wide_65303.s")
    destination.write_text(render(), encoding="ascii", newline="\n")
    print(f"wrote {destination} with {SECTIONS} declared sections")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
