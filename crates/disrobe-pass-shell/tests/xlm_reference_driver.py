from __future__ import annotations

import importlib.metadata as metadata
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import TypedDict

CETAB_FLAG: int = 0x8000
CETAB_MASK: int = 0x7FFF


class FunctionTables(TypedDict):
    pyxlsb2: str
    xlmmacrodeobfuscator: str
    xlrd2: str
    symbol: str
    ftab: dict[str, str]
    cetab: dict[str, str]
    parser_ids: list[str]


class CellAnswer(TypedDict):
    status: str
    formula: str
    detail: str


class CellJob(TypedDict):
    key: str
    file: str
    sheet: str
    cell: str


def function_tables() -> FunctionTables:
    import pyxlsb2.ptgs as ptgs
    import xlrd2.formula as parser

    ftab: dict[str, str] = {}
    cetab: dict[str, str] = {}
    for key, entry in ptgs.function_names.items():
        identifier: int = int(key)
        name: str = str(entry[0])
        if identifier & CETAB_FLAG:
            cetab[f"0x{identifier & CETAB_MASK:04X}"] = name
        else:
            ftab[f"0x{identifier:04X}"] = name
    return {
        "pyxlsb2": metadata.version("pyxlsb2"),
        "xlmmacrodeobfuscator": metadata.version("XLMMacroDeobfuscator"),
        "xlrd2": metadata.version("xlrd2"),
        "symbol": "pyxlsb2.ptgs.function_names",
        "ftab": ftab,
        "cetab": cetab,
        "parser_ids": sorted(f"0x{int(key):04X}" for key in parser.func_defs),
    }


def read_one(path: Path, sheet: str, cell: str, /) -> CellAnswer:
    from XLMMacroDeobfuscator.deobfuscator import XLSWrapper2, show_cells

    chatter: io.StringIO = io.StringIO()
    try:
        with redirect_stdout(chatter):
            document = XLSWrapper2(str(path))
            for entry in show_cells(document):
                if isinstance(entry, tuple) and len(entry) == 2:
                    continue
                info = entry[0]
                where: str = f"{info.column}{info.row}"
                if getattr(info.sheet, "name", None) != sheet or where != cell:
                    continue
                if info.formula is None:
                    return {"status": "absent", "formula": "", "detail": "the cell carries no formula"}
                return {"status": "named", "formula": str(info.formula), "detail": ""}
    except Exception as failure:
        return {
            "status": "refused",
            "formula": "",
            "detail": f"{type(failure).__name__}: {failure}",
        }
    tail: list[str] = chatter.getvalue().strip().splitlines()
    return {
        "status": "absent",
        "formula": "",
        "detail": tail[-1] if tail else "the reference reported no such cell",
    }


def read_cells(job_path: Path, /) -> dict[str, CellAnswer]:
    jobs: list[CellJob] = json.loads(job_path.read_text(encoding="utf-8"))
    answers: dict[str, CellAnswer] = {}
    for job in jobs:
        answers[job["key"]] = read_one(Path(job["file"]), job["sheet"], job["cell"])
    return answers


def main(argv: list[str], /) -> int:
    mode: str = argv[1]
    if mode == "tables":
        Path(argv[2]).write_text(json.dumps(function_tables()), encoding="utf-8")
        return 0
    if mode == "cells":
        Path(argv[3]).write_text(json.dumps(read_cells(Path(argv[2]))), encoding="utf-8")
        return 0
    sys.stderr.write(f"unknown mode {mode!r}, expected tables or cells\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
