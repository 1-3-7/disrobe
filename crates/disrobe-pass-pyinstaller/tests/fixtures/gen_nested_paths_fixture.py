"""Build the real PyInstaller CArchive that carries Windows-style nested TOC names.

The archive is written by PyInstaller's own ``CArchiveWriter`` and read back by
PyInstaller's own ``CArchiveReader``. Neither disrobe nor any disrobe code takes part,
so ``nested_paths.expected.json`` is a reference independent of the parser it grades.

Run on Windows, where ``CArchiveWriter`` applies ``os.path.normpath`` and therefore
stores nested destinations with back slashes, exactly as a real Windows build does.

    python -m venv venv
    venv/Scripts/pip install pyinstaller==6.22.0
    venv/Scripts/python gen_nested_paths_fixture.py <corpus-dir>
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import py_compile
import shutil
import sys
import tempfile
from typing import Final

from PyInstaller import __version__ as pyinstaller_version
from PyInstaller.archive.readers import CArchiveReader
from PyInstaller.archive.writers import CArchiveWriter

ARCHIVE_NAME: Final[str] = "nested_paths.bin"
EXPECTED_NAME: Final[str] = "nested_paths.expected.json"
SCHEMA: Final[str] = "disrobe.corpus.pyinstaller-nested-paths/v1"

SCRIPT_SOURCE: Final[bytes] = (
    b"import mypkg.util\n\n\ndef main():\n"
    b"    print(mypkg.util.greeting())\n\n\n"
    b"if __name__ == '__main__':\n    main()\n"
)
MODULE_SOURCE: Final[bytes] = b"GREETING = 'nested-paths'\n\n\ndef greeting():\n    return GREETING\n"
CONFIG_BYTES: Final[bytes] = b'{"nested": true, "depth": 2}\n'
CACERT_BYTES: Final[bytes] = b"-----BEGIN CERTIFICATE-----\nnested data payload\n"
SPEEDUP_BYTES: Final[bytes] = b"MZ" + bytes(190) + b"fake-extension-payload"

MERGE_REFERENCE: Final[str] = os.path.join("..", "app_b", "app_b.exe")


def _stage(work: pathlib.Path, name: str, data: bytes, /) -> str:
    path: pathlib.Path = work / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return str(path)


def _build(work: pathlib.Path, archive: pathlib.Path, /) -> None:
    script_src: str = _stage(work, "hello.py", SCRIPT_SOURCE)
    module_py: str = _stage(work, "util.py", MODULE_SOURCE)
    module_src: str = py_compile.compile(module_py, cfile=str(work / "util.pyc"), doraise=True)
    config_src: str = _stage(work, "config.json", CONFIG_BYTES)
    cacert_src: str = _stage(work, "cacert.pem", CACERT_BYTES)
    speedup_src: str = _stage(work, "_speedup.pyd", SPEEDUP_BYTES)

    entries: list[tuple[str, str, bool, str]] = [
        ("hello", script_src, True, "s"),
        ("mypkg.util", module_src, True, "m"),
        ("mypkg/data/config.json", config_src, False, "x"),
        ("certifi/cacert.pem", cacert_src, True, "x"),
        ("vendor/native/_speedup.pyd", speedup_src, True, "b"),
        ("mypkg/data/shared.bin", MERGE_REFERENCE, False, "d"),
        ("pyi-disable-windowed-traceback", "", False, "o"),
    ]
    CArchiveWriter(
        str(archive),
        entries,
        f"python{sys.version_info[0]}{sys.version_info[1]}.dll",
    )


def _describe(archive: pathlib.Path, /) -> dict[str, object]:
    reader: CArchiveReader = CArchiveReader(str(archive))
    blob: bytes = archive.read_bytes()
    described: list[dict[str, object]] = []
    for name, entry in sorted(reader.toc.items()):
        entry_offset, data_length, uncompressed_length, compression_flag, typecode = entry
        payload: bytes = reader.extract(name)
        described.append(
            {
                "name": name,
                "typecode": typecode,
                "compression_flag": int(compression_flag),
                "data_length": int(data_length),
                "uncompressed_length": int(uncompressed_length),
                "payload_hex": payload.hex(),
            }
        )
    return {
        "schema": SCHEMA,
        "producer": {
            "tool": "pyinstaller",
            "tool_version": pyinstaller_version,
            "writer": "PyInstaller.archive.writers.CArchiveWriter",
            "reference_reader": "PyInstaller.archive.readers.CArchiveReader",
            "python": sys.version.split()[0],
            "host_platform": "win_amd64",
        },
        "archive": {
            "file": ARCHIVE_NAME,
            "size": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "python_libname": f"python{sys.version_info[0]}{sys.version_info[1]}.dll",
            "pyvers": sys.version_info[0] * 100 + sys.version_info[1],
        },
        "options": list(reader.options),
        "entries": described,
    }


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <corpus-dir>")
    out_dir: pathlib.Path = pathlib.Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    archive: pathlib.Path = out_dir / ARCHIVE_NAME

    work: pathlib.Path = pathlib.Path(tempfile.mkdtemp(prefix="disrobe-pyi-nested-"))
    try:
        _build(work, archive)
        expected: dict[str, object] = _describe(archive)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    (out_dir / EXPECTED_NAME).write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {archive} and {out_dir / EXPECTED_NAME}")


if __name__ == "__main__":
    main()
