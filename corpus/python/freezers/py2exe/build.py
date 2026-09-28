"""Freeze the edge-case application with py2exe and record the PYTHONSCRIPT reference read by pefile."""

from __future__ import annotations

import hashlib
import json
import marshal
import shutil
import struct
import sys
import tempfile
import types
from importlib.metadata import version
from pathlib import Path

import pefile
import py2exe

HERE: Path = Path(__file__).resolve().parent
FREEZERS: Path = HERE.parent
PLAYGROUND: Path = FREEZERS.parent / "decompile" / "playground"
PACKAGE_INIT: Path = FREEZERS / "zipapp" / "extracted" / "hello" / "__init__.py"
BANDS: tuple[str, ...] = (
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
)
ENTRY_SOURCE: str = "from hello import main\n\nmain()\n"
EXCLUDES: tuple[str, ...] = (
    "tkinter",
    "unittest",
    "pydoc",
    "doctest",
    "pdb",
    "email",
    "http",
    "xml",
)
MAGIC_TAG: int = 0x78563412


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stage(root: Path) -> Path:
    package: Path = root / "hello"
    package.mkdir()
    shutil.copyfile(PACKAGE_INIT, package / "__init__.py")
    for band in BANDS:
        shutil.copyfile(PLAYGROUND / f"{band}.py", root / f"{band}.py")
    entry: Path = root / "hello_entry.py"
    entry.write_text(ENTRY_SOURCE, encoding="utf-8")
    return entry


def pythonscript_resource(exe: Path) -> dict[str, object]:
    pe: pefile.PE = pefile.PE(str(exe), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    matches: list[tuple[int, int, int, int]] = []
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if type_entry.name is None or str(type_entry.name) != "PYTHONSCRIPT":
            continue
        for name_entry in type_entry.directory.entries:
            for language_entry in name_entry.directory.entries:
                matches.append(
                    (
                        name_entry.id,
                        language_entry.id,
                        language_entry.data.struct.OffsetToData,
                        language_entry.data.struct.Size,
                    )
                )
    if len(matches) != 1:
        raise SystemExit(f"expected one PYTHONSCRIPT resource, found {matches}")
    resource_id, language, rva, size = matches[0]
    data: bytes = pe.get_data(rva, size)
    if len(data) != size:
        raise SystemExit(f"PYTHONSCRIPT data is {len(data)} bytes, directory says {size}")
    magic, optimize, unbuffered, script_len = struct.unpack_from("<IIII", data, 0)
    if magic != MAGIC_TAG:
        raise SystemExit(f"PYTHONSCRIPT magic {magic:#x}")
    name_end: int = data.index(b"\0", 16)
    zip_name: str = data[16:name_end].decode("ascii")
    script: bytes = data[name_end + 1 : name_end + 1 + script_len]
    if len(script) != script_len:
        raise SystemExit("PYTHONSCRIPT script data is truncated")
    loaded: object = marshal.loads(script)
    if not isinstance(loaded, list) or not all(
        isinstance(item, types.CodeType) for item in loaded
    ):
        raise SystemExit(f"script data loads as {type(loaded).__name__}, not a list of code")
    return {
        "type": "PYTHONSCRIPT",
        "id": resource_id,
        "language": language,
        "rva": rva,
        "size": size,
        "sha256": sha256(data),
        "magic_tag": magic,
        "optimize": optimize,
        "unbuffered": unbuffered,
        "script_data_len": script_len,
        "zip_archive_name": zip_name,
        "script_data_sha256": sha256(script),
        "marshal_loads": {
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "type": "list",
            "code_objects": [
                {"co_filename": code.co_filename, "co_name": code.co_name}
                for code in loaded
            ],
        },
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="disrobe-py2exe-build-") as scratch:
        root: Path = Path(scratch)
        entry: Path = stage(root)
        dist: Path = root / "dist"
        sys.path.insert(0, str(root))
        py2exe.freeze(
            console=[{"script": str(entry), "dest_base": "hello"}],
            zipfile="library.zip",
            options={
                "bundle_files": 3,
                "compressed": 1,
                "optimize": 0,
                "dist_dir": str(dist),
                "excludes": list(EXCLUDES),
            },
        )
        outputs: dict[str, dict[str, object]] = {}
        for produced in sorted(dist.rglob("*")):
            if produced.is_file():
                data: bytes = produced.read_bytes()
                outputs[produced.relative_to(dist).as_posix()] = {
                    "size": len(data),
                    "sha256": sha256(data),
                }
        for committed in ("hello.exe", "library.zip"):
            shutil.copyfile(dist / committed, HERE / committed)
        resource: dict[str, object] = pythonscript_resource(HERE / "hello.exe")
    record: dict[str, object] = {
        "python": sys.version.split()[0],
        "py2exe": version("py2exe"),
        "pefile": version("pefile"),
        "committed": ["hello.exe", "library.zip"],
        "outputs": outputs,
        "pythonscript": resource,
    }
    (HERE / "hello.expected.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
