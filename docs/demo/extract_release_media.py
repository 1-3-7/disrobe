from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path
from typing import IO

FILES: tuple[str, ...] = (
    "walkthrough.mp4", "teaser.mp4", "preview.gif", "poster.png", "captions.vtt",
    "chapters.vtt", "teaser.vtt", "transcript.txt", "media.json", "cli-recording.json",
)
MAX_ARCHIVE_BYTES: int = 32 * 1024 * 1024
MAX_FILE_BYTES: int = 10 * 1024 * 1024


def validate_archive(path: Path) -> dict[str, bytes]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ARCHIVE_BYTES:
        raise ValueError("release media tar must be a regular file of at most 32 MiB")
    payload: bytes = path.read_bytes()
    expected: set[str] = {f"walkthrough/{name}" for name in FILES}
    files: dict[str, bytes] = {}
    offset: int = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        member: tarfile.TarInfo
        for member in archive:
            if member.name not in expected or member.name in files:
                raise ValueError(f"unexpected or duplicate release media member: {member.name}")
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.issparse():
                raise ValueError(f"release media member must be a regular file: {member.name}")
            if member.offset != offset or member.offset_data != offset + 512 or member.pax_headers:
                raise ValueError("release media archive contains extended headers")
            if not 0 < member.size < MAX_FILE_BYTES:
                raise ValueError(f"release media member exceeds its size limit: {member.name}")
            stream: IO[bytes] | None = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"release media member has no file content: {member.name}")
            with stream:
                content: bytes = stream.read(member.size + 1)
            if len(content) != member.size:
                raise ValueError(f"release media member is truncated: {member.name}")
            files[member.name] = content
            offset = member.offset_data + ((member.size + 511) // 512) * 512
    if set(files) != expected:
        raise ValueError("release media archive must contain all ten expected files")
    if len(payload) % 512 or len(payload) - offset < 1024 or any(payload[offset:]):
        raise ValueError("release media archive contains trailing content")
    return {name: files[f"walkthrough/{name}"] for name in FILES}


def extract_archive(path: Path, destination: Path) -> None:
    files: dict[str, bytes] = validate_archive(path)
    destination.mkdir()
    name: str
    content: bytes
    for name, content in files.items():
        with (destination / name).open("xb") as target:
            target.write(content)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: python3 docs/demo/extract_release_media.py <media.tar> <new-directory>")
    extract_archive(Path(sys.argv[1]), Path(sys.argv[2]))
