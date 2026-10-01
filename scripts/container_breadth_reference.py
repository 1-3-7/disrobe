"""Record reference member hashes for the container-breadth evidence.

For every input that crates/disrobe-cli/tests/golden/container_breadth.txt credits
with member bytes, extract it with an independent tool (bsdtar, 7-Zip or the
format's own decompressor) and write the SHA-256 of every non-empty member to
crates/disrobe-cli/tests/golden/container_breadth_reference.tsv. The breadth test
counts a format as extracted only when a member disrobe writes has one of these
hashes. Formats no installed tool reads get no rows and stay uncounted.

Usage: python scripts/container_breadth_reference.py
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "crates/disrobe-cli/tests/golden/container_breadth.txt"
REFERENCE = ROOT / "crates/disrobe-cli/tests/golden/container_breadth_reference.tsv"
TIMEOUT_SECONDS = 120
MAX_MEMBER_BYTES = 256 * 1024 * 1024

BSDTAR = ["zip", "tar", "tar.gz", "rar", "iso", "pkg", "rpm", "jar", "apk", "pyz", "cpio", "ar", "lzh", "msix", "oci", "docker-image"]
SEVEN_ZIP = ["arj", "squashfs", "vhd", "vhdx", "wim", "dmg", "uefi-fv", "appimage", "lz", "msi", "ext4", "cramfs", "snap", "7z"]
STREAMS = {
    "gz": ["gzip", "-dc"],
    "Z": ["gzip", "-dc"],
    "bz2": ["bzip2", "-dc"],
    "xz": ["xz", "-dc"],
    "lzma": ["xz", "--format=lzma", "-dc"],
    "zst": ["zstd", "-dc"],
    "lz4": ["lz4", "-dc"],
}


def tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        sys.exit(f"{name} is not on PATH; it is the reference extractor for part of the roster")
    return found


def run(argv: list[str], cwd: pathlib.Path | None = None, stdin: bytes | None = None) -> bytes | None:
    result = subprocess.run(argv, cwd=cwd, input=stdin, capture_output=True, timeout=TIMEOUT_SECONDS)
    if result.returncode != 0:
        return None
    return result.stdout


def member_hashes(directory: pathlib.Path) -> set[str]:
    hashes: set[str] = set()
    for path in directory.rglob("*"):
        if path.is_file() and not path.is_symlink():
            size = path.stat().st_size
            if 0 < size <= MAX_MEMBER_BYTES:
                hashes.add(hashlib.sha256(path.read_bytes()).hexdigest())
    return hashes


def gzip_member_hashes(data: bytes) -> set[str]:
    hashes: set[str] = set()
    whole = b""
    rest = data
    while rest.startswith(b"\x1f\x8b"):
        decoder = zlib.decompressobj(31)
        member = decoder.decompress(rest)
        hashes.add(hashlib.sha256(member).hexdigest())
        whole += member
        rest = decoder.unused_data
    hashes.add(hashlib.sha256(whole).hexdigest())
    return hashes


def reference(label: str, source: pathlib.Path) -> tuple[str, set[str]] | None:
    data = source.read_bytes()
    if label == "gz":
        return ("zlib-gzip-members", gzip_member_hashes(data))
    if label in STREAMS:
        argv = STREAMS[label]
        out = run([tool(argv[0]), *argv[1:]], stdin=data)
        return (argv[0], {hashlib.sha256(out).hexdigest()}) if out else None
    if label == "zlib":
        try:
            out = zlib.decompress(data)
        except zlib.error:
            return None
        return ("zlib", {hashlib.sha256(out).hexdigest()}) if out else None
    with tempfile.TemporaryDirectory() as scratch:
        out_dir = pathlib.Path(scratch)
        if label in BSDTAR:
            name = "bsdtar"
            run([tool("bsdtar"), "-xf", str(source), "-C", str(out_dir)])
        elif label in SEVEN_ZIP:
            name = "7z"
            run([tool("7z"), "x", "-y", "-bd", f"-o{out_dir}", str(source)])
        else:
            return None
        hashes = member_hashes(out_dir) - {hashlib.sha256(data).hexdigest()}
        return (name, hashes) if hashes else None


def main() -> None:
    rows: list[str] = []
    for line in GOLDEN.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[1] == "detect-only":
            continue
        label, _, relative = parts
        found = reference(label, ROOT / relative)
        if found is None:
            continue
        name, hashes = found
        rows.extend(f"{label}\t{relative}\t{digest}\t{name}" for digest in sorted(hashes))
    REFERENCE.write_text("".join(f"{row}\n" for row in rows), encoding="utf-8", newline="\n")
    formats = len({row.split("\t")[0] for row in rows})
    print(f"{len(rows)} reference member hash(es) over {formats} format(s) -> {REFERENCE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
