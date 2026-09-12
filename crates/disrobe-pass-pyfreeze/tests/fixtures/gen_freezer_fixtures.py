from __future__ import annotations

import importlib.util
import io
import marshal
import os
import struct
import zipfile
from pathlib import Path

WORKTREE_ROOT: Path = Path(__file__).resolve().parent.parent.parent.parent.parent
FREEZERS: Path = WORKTREE_ROOT / "corpus" / "python" / "freezers"
SOURCES: Path = FREEZERS / "briefcase" / "extracted" / "app" / "hello"

BANDS: list[str] = [
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
]

MAGIC: bytes = importlib.util.MAGIC_NUMBER


def compile_band(name: str) -> bytes:
    src_path: Path = SOURCES / f"{name}.py"
    src: str = src_path.read_text(encoding="utf-8")
    code = compile(src, f"{name}.py", "exec")
    body: bytes = marshal.dumps(code)
    header: bytes = MAGIC + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 4
    return header + body


def marshal_body(name: str) -> bytes:
    src_path: Path = SOURCES / f"{name}.py"
    src: str = src_path.read_text(encoding="utf-8")
    code = compile(src, f"{name}.py", "exec")
    return marshal.dumps(code)


def make_zip(entries: list[tuple[str, bytes]], /) -> bytes:
    buf: io.BytesIO = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in entries:
            info: zipfile.ZipInfo = zipfile.ZipInfo(name)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, data)
    return buf.getvalue()


def make_minimal_pe() -> bytes:
    buf: bytearray = bytearray(0x80)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\x00\x00"
    return bytes(buf)


def make_py2exe_pe(marshalled_code: bytes) -> bytes:
    PY2EXE_MAGIC_TAG: int = 0x78563412
    header: bytearray = bytearray(0x80)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\x00\x00"
    payload: bytes = b"PYTHONSCRIPT"
    blob: bytearray = bytearray()
    blob += struct.pack("<I", PY2EXE_MAGIC_TAG)
    blob += struct.pack("<I", 2)
    blob += struct.pack("<I", 0)
    blob += struct.pack("<I", 1)
    blob += b"app.zip\x00"
    blob += marshalled_code
    return bytes(header) + payload + bytes(blob)


def make_pex(bands_py: list[tuple[str, str]], pex_info_json: str, /) -> bytes:
    shebang: bytes = b"#!/usr/bin/env python3\n"
    zip_entries: list[tuple[str, bytes]] = [
        ("PEX-INFO", pex_info_json.encode()),
    ]
    for zname, content in bands_py:
        zip_entries.append((zname, content.encode()))
    return shebang + make_zip(zip_entries)


def gen_cxfreeze() -> None:
    out_dir: Path = FREEZERS / "cxfreeze" / "extracted"
    out_dir.mkdir(parents=True, exist_ok=True)

    exe_path: Path = out_dir / "hello.exe"
    exe_path.write_bytes(make_minimal_pe())

    pyc_entries: list[tuple[str, bytes]] = []
    for band in BANDS:
        pyc_entries.append((f"{band}.pyc", compile_band(band)))
    zip_path: Path = out_dir / "library.zip"
    zip_path.write_bytes(make_zip(pyc_entries))


def gen_pex() -> None:
    out_dir: Path = FREEZERS / "pex"
    out_dir.mkdir(parents=True, exist_ok=True)

    pex_info: str = '{"entry_point":"hello:main","interpreter_constraints":["CPython>=3.9"]}'
    bands_py: list[tuple[str, str]] = []
    for band in BANDS:
        src: str = (SOURCES / f"{band}.py").read_text(encoding="utf-8")
        zip_name: str = f".deps/hello-0.1.0-py3-none-any.whl/{band}.py"
        bands_py.append((zip_name, src))
    pex_bytes: bytes = make_pex(bands_py, pex_info)

    pex_path: Path = out_dir / "hello.pex"
    pex_path.write_bytes(pex_bytes)


def gen_py2exe() -> None:
    out_dir: Path = FREEZERS / "py2exe"
    extracted_dir: Path = out_dir / "extracted"
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)

    first_band_marshal: bytes = marshal_body(BANDS[0])
    exe_bytes: bytes = make_py2exe_pe(first_band_marshal)
    exe_path: Path = out_dir / "hello.exe"
    exe_path.write_bytes(exe_bytes)

    pyc_entries: list[tuple[str, bytes]] = []
    for band in BANDS:
        pyc_entries.append((f"{band}.pyc", compile_band(band)))
    zip_path: Path = extracted_dir / "library.zip"
    zip_path.write_bytes(make_zip(pyc_entries))


if __name__ == "__main__":
    gen_cxfreeze()
    gen_pex()
    gen_py2exe()
    print("fixtures generated")
