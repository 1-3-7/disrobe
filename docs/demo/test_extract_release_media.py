from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from extract_release_media import FILES, MAX_FILE_BYTES, extract_archive, validate_archive


def regular(name: str) -> tuple[tarfile.TarInfo, bytes]:
    content: bytes = b"recorded media"
    member: tarfile.TarInfo = tarfile.TarInfo(name)
    member.size = len(content)
    return member, content


def expected_entries() -> list[tuple[tarfile.TarInfo, bytes]]:
    return [regular(f"walkthrough/{name}") for name in FILES]


def write_archive(path: Path, entries: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        member: tarfile.TarInfo
        content: bytes
        for member, content in entries:
            archive.addfile(member, io.BytesIO(content))


class MediaArchiveTests(unittest.TestCase):
    def reject(self: MediaArchiveTests, entries: list[tuple[tarfile.TarInfo, bytes]], message: str) -> None:
        with tempfile.TemporaryDirectory(prefix=".media-archive-", dir=Path(__file__).parent) as name:
            root: Path = Path(name)
            archive: Path = root / "media.tar"
            destination: Path = root / "extracted"
            write_archive(archive, entries)
            with self.assertRaisesRegex(ValueError, message):
                extract_archive(archive, destination)
            self.assertFalse(destination.exists(), "invalid archive created an extraction directory")

    def test_exact_regular_files_extract(self: MediaArchiveTests) -> None:
        with tempfile.TemporaryDirectory(prefix=".media-archive-", dir=Path(__file__).parent) as name:
            root: Path = Path(name)
            archive: Path = root / "media.tar"
            destination: Path = root / "extracted"
            write_archive(archive, expected_entries())
            extract_archive(archive, destination)
            self.assertEqual(sorted(path.name for path in destination.iterdir()), sorted(FILES))
            for path in destination.iterdir():
                self.assertTrue(path.is_file() and not path.is_symlink())
                self.assertEqual(path.read_bytes(), b"recorded media")

    def test_extra_player_page_is_rejected(self: MediaArchiveTests) -> None:
        self.reject([*expected_entries(), regular("walkthrough/watch.html")], "unexpected or duplicate")

    def test_symlink_is_rejected(self: MediaArchiveTests) -> None:
        entries: list[tuple[tarfile.TarInfo, bytes]] = expected_entries()
        member: tarfile.TarInfo = entries[0][0]
        member.type = tarfile.SYMTYPE
        member.linkname = "../watch.html"
        member.size = 0
        entries[0] = member, b""
        self.reject(entries, "must be a regular file")

    def test_hardlink_is_rejected(self: MediaArchiveTests) -> None:
        entries: list[tuple[tarfile.TarInfo, bytes]] = expected_entries()
        member: tarfile.TarInfo = entries[0][0]
        member.type = tarfile.LNKTYPE
        member.linkname = "walkthrough/poster.png"
        member.size = 0
        entries[0] = member, b""
        self.reject(entries, "must be a regular file")

    def test_duplicate_is_rejected(self: MediaArchiveTests) -> None:
        entries: list[tuple[tarfile.TarInfo, bytes]] = expected_entries()
        self.reject([*entries, entries[0]], "unexpected or duplicate")

    def test_missing_member_is_rejected(self: MediaArchiveTests) -> None:
        self.reject(expected_entries()[:-1], "all ten expected files")

    def test_missing_preview_is_rejected(self: MediaArchiveTests) -> None:
        entries: list[tuple[tarfile.TarInfo, bytes]] = [
            entry for entry in expected_entries() if entry[0].name != "walkthrough/preview.gif"
        ]
        self.reject(entries, "all ten expected files")

    def test_path_traversal_is_rejected(self: MediaArchiveTests) -> None:
        self.reject([*expected_entries(), regular("walkthrough/../../watch.html")], "unexpected or duplicate")

    def test_oversized_member_is_rejected_before_reading(self: MediaArchiveTests) -> None:
        with tempfile.TemporaryDirectory(prefix=".media-archive-", dir=Path(__file__).parent) as name:
            archive: Path = Path(name) / "media.tar"
            member: tarfile.TarInfo = tarfile.TarInfo("walkthrough/walkthrough.mp4")
            member.size = MAX_FILE_BYTES
            archive.write_bytes(member.tobuf(tarfile.GNU_FORMAT) + bytes(1024))
            with self.assertRaisesRegex(ValueError, "exceeds its size limit"):
                validate_archive(archive)

    def test_content_after_tar_end_is_rejected(self: MediaArchiveTests) -> None:
        with tempfile.TemporaryDirectory(prefix=".media-archive-", dir=Path(__file__).parent) as name:
            archive: Path = Path(name) / "media.tar"
            write_archive(archive, expected_entries())
            archive.write_bytes(archive.read_bytes() * 2)
            with self.assertRaisesRegex(ValueError, "trailing content"):
                validate_archive(archive)


if __name__ == "__main__":
    unittest.main()
