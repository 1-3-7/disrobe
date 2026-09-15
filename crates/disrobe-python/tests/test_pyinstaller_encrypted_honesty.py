"""Regression: an encrypted PyInstaller archive whose AES key was not recovered
must never present the still-encrypted member payloads as recovered plaintext.

Builds a minimal CArchive with a ``pyimod00_crypto_key`` module (so the image
reads as encrypted) whose body yields no recoverable key, plus one encrypted
member. With the key unrecovered the member bytes are ciphertext; the report
must say so rather than list them as recovered ``.pyc`` output or hand the
ciphertext back through ``pyinstaller_entry_bytes``.

Run with: python -m pytest crates/disrobe-python/tests
"""

from __future__ import annotations

import struct

import disrobe

MEI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def _toc_entry(
    position: int,
    csize: int,
    usize: int,
    flag: int,
    type_byte: bytes,
    name: str,
) -> bytes:
    name_bytes = name.encode() + b"\x00"
    entry_size = 18 + len(name_bytes)
    return struct.pack(">IIIIB", entry_size, position, csize, usize, flag) + type_byte + name_bytes


def _archive(entries: list[tuple[str, bytes, bytes]]) -> bytes:
    data_region = b""
    positions: list[int] = []
    for _name, _type, blob in entries:
        positions.append(len(data_region))
        data_region += blob

    toc = b""
    for (name, type_byte, blob), pos in zip(entries, positions):
        toc += _toc_entry(pos, len(blob), len(blob), 0, type_byte, name)

    body = data_region + toc
    cookie = (
        MEI_MAGIC
        + struct.pack(">I", len(body) + 24)
        + struct.pack(">I", len(data_region))
        + struct.pack(">I", len(toc))
        + struct.pack(">I", 311)
    )
    assert len(cookie) == 24
    return body + cookie


def _encrypted_no_key_archive() -> bytes:
    return _archive(
        [
            ("pyimod00_crypto_key", b"m", b"\x00\x01\x02\x03"),
            ("secret", b"m", bytes(range(0x20, 0x20 + 48))),
        ]
    )


def _plain_archive() -> bytes:
    return _archive([("mod", b"m", bytes(range(0x20, 0x20 + 48)))])


def test_encrypted_unrecovered_key_is_not_reported_as_plaintext() -> None:
    img = _encrypted_no_key_archive()
    rep = disrobe.pyinstaller_extract(img)
    raw = rep.raw

    assert rep.encrypted is True
    assert rep.encryption_key_present is False
    assert raw["content_recovered"] is False

    assert "secret.pyc" not in raw["bare_pyc_paths"]
    assert "secret.pyc" in raw["encrypted_unrecovered_paths"]

    secret = next(e for e in raw["entries"] if e["name"] == "secret")
    assert secret["decrypted"] is False
    assert secret["content_encrypted"] is True


def test_entry_bytes_refuses_to_return_ciphertext_as_recovered() -> None:
    img = _encrypted_no_key_archive()
    try:
        disrobe.pyinstaller_entry_bytes(img, "secret")
    except disrobe.DisrobeError as exc:
        assert "encrypt" in str(exc).lower()
    else:
        raise AssertionError("still-encrypted entry bytes must not be returned as recovered")


def test_unencrypted_archive_still_reports_recovered_content() -> None:
    img = _plain_archive()
    rep = disrobe.pyinstaller_extract(img)
    raw = rep.raw

    assert rep.encrypted is False
    assert raw["content_recovered"] is True
    assert "mod.pyc" in raw["bare_pyc_paths"]
    assert raw["encrypted_unrecovered_paths"] == []

    mod = next(e for e in raw["entries"] if e["name"] == "mod")
    assert mod["content_encrypted"] is False

    body = disrobe.pyinstaller_entry_bytes(img, "mod")
    assert isinstance(body, bytes)
    assert len(body) > 0
