from __future__ import annotations

import hashlib
import io
import struct
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path

import msoffcrypto
import msoffcrypto.method.container.ecma376_encrypted as encrypted_container
import msoffcrypto.method.ecma376_agile as agile
import olefile

HERE: Path = Path(__file__).resolve().parent
PASSWORD: str = "disrobe-fixture"
SEED: bytes = b"disrobe office wall fixtures v1"

SECTOR: int = 512
MINI_SECTOR: int = 64
MINI_CUTOFF: int = 4096
HEADER_DIFAT: int = 109
FREESECT: int = 0xFFFFFFFF
ENDOFCHAIN: int = 0xFFFFFFFE
FATSECT: int = 0xFFFFFFFD
NOSTREAM: int = 0xFFFFFFFF
WORD_CLSID: bytes = bytes.fromhex("0609020000000000c000000000000046")
MSG_CLSID: bytes = bytes.fromhex("0b0d020000000000c000000000000046")

MEMO_TEXT: str = (
    "Quarterly planning memo\r"
    "The planning meeting moves to Thursday at 10:00 in room 4.\r"
    "Bring the revised budget sheet and the travel schedule.\r"
)


class Entry:
    def __init__(
        self,
        name: str,
        data: bytes | None = None,
        children: list[Entry] | None = None,
        clsid: bytes = bytes(16),
    ) -> None:
        self.name: str = name
        self.data: bytes | None = data
        self.children: list[Entry] | None = children
        self.clsid: bytes = clsid
        self.index: int = 0
        self.left: int = NOSTREAM
        self.right: int = NOSTREAM
        self.child: int = NOSTREAM
        self.start: int = 0 if children is not None else ENDOFCHAIN
        self.size: int = 0


def name_key(entry: Entry) -> tuple[int, str]:
    return (len(entry.name), entry.name.upper())


def balanced(entries: list[Entry]) -> Entry | None:
    if not entries:
        return None
    middle: int = len(entries) // 2
    node: Entry = entries[middle]
    left: Entry | None = balanced(entries[:middle])
    right: Entry | None = balanced(entries[middle + 1 :])
    node.left = NOSTREAM if left is None else left.index
    node.right = NOSTREAM if right is None else right.index
    return node


def empty_directory_entry() -> bytes:
    return bytes(64) + struct.pack("<HBBIII", 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM) + bytes(48)


def compound_file(children: list[Entry], root_clsid: bytes) -> bytes:
    root: Entry = Entry("Root Entry", children=children, clsid=root_clsid)
    order: list[Entry] = [root]
    pending: list[Entry] = [root]
    while pending:
        storage: Entry = pending.pop(0)
        for entry in sorted(storage.children or [], key=name_key):
            entry.index = len(order)
            order.append(entry)
            if entry.children is not None:
                pending.append(entry)
    for storage in order:
        if storage.children is not None:
            top: Entry | None = balanced(sorted(storage.children, key=name_key))
            storage.child = NOSTREAM if top is None else top.index

    sectors: list[bytes] = []
    fat: list[int] = []

    def place(data: bytes) -> int:
        count: int = (len(data) + SECTOR - 1) // SECTOR
        first: int = len(sectors)
        for offset in range(count):
            sectors.append(data[offset * SECTOR : (offset + 1) * SECTOR].ljust(SECTOR, b"\0"))
            fat.append(first + offset + 1 if offset + 1 < count else ENDOFCHAIN)
        return first if count else ENDOFCHAIN

    mini_stream: bytearray = bytearray()
    mini_fat: list[int] = []
    for entry in order[1:]:
        if entry.data is None:
            continue
        entry.size = len(entry.data)
        if entry.size == 0:
            continue
        if entry.size >= MINI_CUTOFF:
            entry.start = place(entry.data)
            continue
        count: int = (entry.size + MINI_SECTOR - 1) // MINI_SECTOR
        first: int = len(mini_fat)
        for offset in range(count):
            mini_fat.append(first + offset + 1 if offset + 1 < count else ENDOFCHAIN)
        entry.start = first
        mini_stream += entry.data.ljust(count * MINI_SECTOR, b"\0")

    root.size = len(mini_stream)
    root.start = place(bytes(mini_stream)) if mini_stream else ENDOFCHAIN
    mini_fat_bytes: bytes = struct.pack(f"<{len(mini_fat)}I", *mini_fat)
    mini_fat_start: int = place(mini_fat_bytes) if mini_fat else ENDOFCHAIN
    mini_fat_sectors: int = (len(mini_fat_bytes) + SECTOR - 1) // SECTOR

    directory: bytearray = bytearray()
    for entry in order:
        encoded: bytes = (entry.name + "\0").encode("utf-16-le")
        kind: int = 5 if entry is root else (1 if entry.children is not None else 2)
        directory += encoded.ljust(64, b"\0")
        directory += struct.pack("<HBBIII", len(encoded), kind, 1, entry.left, entry.right, entry.child)
        directory += entry.clsid
        directory += struct.pack("<IQQIQ", 0, 0, 0, entry.start, entry.size)
    while len(directory) % SECTOR:
        directory += empty_directory_entry()
    directory_start: int = place(bytes(directory))

    fat_sector_count: int = 1
    while len(sectors) + fat_sector_count > fat_sector_count * (SECTOR // 4):
        fat_sector_count += 1
    if fat_sector_count > HEADER_DIFAT:
        raise SystemExit("the fixture writer keeps the whole FAT in the header DIFAT")
    fat_start: int = len(sectors)
    fat.extend([FATSECT] * fat_sector_count)
    fat.extend([FREESECT] * (fat_sector_count * (SECTOR // 4) - len(fat)))
    fat_bytes: bytes = struct.pack(f"<{len(fat)}I", *fat)
    for offset in range(fat_sector_count):
        sectors.append(fat_bytes[offset * SECTOR : (offset + 1) * SECTOR])

    difat: list[int] = [fat_start + offset for offset in range(fat_sector_count)]
    difat.extend([FREESECT] * (HEADER_DIFAT - len(difat)))
    header: bytearray = bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    header += bytes(16)
    header += struct.pack("<HHHHH", 0x003E, 0x0003, 0xFFFE, 9, 6)
    header += bytes(6)
    header += struct.pack(
        "<IIIIIIIII",
        0,
        fat_sector_count,
        directory_start,
        0,
        MINI_CUTOFF,
        mini_fat_start,
        mini_fat_sectors,
        ENDOFCHAIN,
        0,
    )
    header += struct.pack(f"<{HEADER_DIFAT}I", *difat)
    if len(header) != SECTOR:
        raise SystemExit(f"compound file header is {len(header)} bytes")
    return bytes(header) + b"".join(sectors)


def word_document() -> tuple[bytes, dict[str, bytes]]:
    text: bytes = MEMO_TEXT.encode("cp1252")
    text_offset: int = 0x400
    fib_base: bytes = struct.pack(
        "<HHHHHHHIBBHHII",
        0xA5EC,
        0x00C1,
        0,
        0x0409,
        0,
        (1 << 9) | (1 << 12),
        0x00BF,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    fib_rg_lw: list[int] = [0] * 22
    fib_rg_lw[0] = text_offset + len(text)
    fib_rg_lw[3] = len(MEMO_TEXT)
    clx: bytes = struct.pack("<BI", 0x02, 16) + struct.pack(
        "<IIHIH", 0, len(MEMO_TEXT), 0, (text_offset * 2) | 0x40000000, 0
    )
    fc_lcb: list[int] = [0] * (0x5D * 2)
    fc_lcb[33 * 2 + 1] = len(clx)
    fib: bytes = (
        fib_base
        + struct.pack("<H", 14)
        + bytes(28)
        + struct.pack("<H", 22)
        + struct.pack("<22I", *fib_rg_lw)
        + struct.pack("<H", 0x5D)
        + struct.pack(f"<{len(fc_lcb)}I", *fc_lcb)
        + struct.pack("<H", 0)
    )
    if fib[0x1A2:0x1AA] != struct.pack("<II", 0, len(clx)):
        raise SystemExit("fcClx and lcbClx are not at FIB offset 0x1A2")
    streams: dict[str, bytes] = {"WordDocument": fib.ljust(text_offset, b"\0") + text, "1Table": clx}
    children: list[Entry] = [Entry(name, data=data) for name, data in streams.items()]
    return compound_file(children, WORD_CLSID), streams


def outlook_message() -> tuple[bytes, dict[str, bytes]]:
    subject: str = "Quarterly planning memo"
    properties: list[tuple[int, str]] = [
        (0x001A001F, "IPM.Note"),
        (0x0037001F, subject),
        (0x0C1A001F, "Planning Office"),
        (0x0E1D001F, subject),
        (0x1000001F, MEMO_TEXT.replace("\r", "\r\n")),
    ]
    streams: dict[str, bytes] = {}
    property_stream: bytearray = bytearray(bytes(8) + struct.pack("<IIII", 0, 0, 0, 0) + bytes(8))
    for tag, value in properties:
        data: bytes = (value + "\0").encode("utf-16-le")
        streams[f"__substg1.0_{tag:08X}"] = data
        property_stream += struct.pack("<IIII", tag, 0x6, len(data), 0)
    property_stream += struct.pack("<IIQ", 0x0E070003, 0x6, 0x00000001)
    streams["__properties_version1.0"] = bytes(property_stream)
    named: dict[str, bytes] = {
        "__substg1.0_00020102": b"",
        "__substg1.0_00030102": b"",
        "__substg1.0_00040102": b"",
    }
    children: list[Entry] = [Entry(name, data=data) for name, data in streams.items()]
    children.append(
        Entry(
            "__nameid_version1.0",
            children=[Entry(name, data=data) for name, data in named.items()],
        )
    )
    listed: dict[str, bytes] = dict(streams)
    listed.update({f"__nameid_version1.0/{name}": data for name, data in named.items()})
    return compound_file(children, MSG_CLSID), listed


def wordprocessing_package() -> bytes:
    lines: list[str] = [line for line in MEMO_TEXT.split("\r") if line]
    lines.extend(
        f"Week {week}: regional office {week % 7 + 1} reports travel, budget and staffing figures."
        for week in range(1, 53)
    )
    paragraphs: str = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in lines)
    parts: dict[str, str] = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>"
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>'
            "</Relationships>"
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body>{paragraphs}</w:body></w:document>"
        ),
    }
    buffer: io.BytesIO = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in parts.items():
            info: zipfile.ZipInfo = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            archive.writestr(info, text.encode("utf-8"))
    package: bytes = buffer.getvalue()
    if len(package) < MINI_CUTOFF:
        raise SystemExit("msoffcrypto-tool writes EncryptedPackage as a regular stream; keep it above 4096 bytes")
    return package


def pinned_random() -> Callable[[int], bytes]:
    counter: list[int] = [0]

    def draw(size: int) -> bytes:
        out: bytearray = bytearray()
        while len(out) < size:
            out += hashlib.sha256(SEED + counter[0].to_bytes(8, "little")).digest()
            counter[0] += 1
        return bytes(out[:size])

    return draw


def encrypted_document(package: bytes) -> bytes:
    agile._random_buffer = pinned_random()
    encrypted_container.datetime2filetime = lambda _moment: 0
    output: io.BytesIO = io.BytesIO()
    msoffcrypto.OfficeFile(io.BytesIO(package)).encrypt(PASSWORD, output)
    return output.getvalue()


def check_streams(path: Path, expected: dict[str, bytes]) -> None:
    with olefile.OleFileIO(str(path)) as ole:
        listed: set[str] = {"/".join(parts) for parts in ole.listdir(streams=True, storages=False)}
        if listed != set(expected):
            raise SystemExit(f"{path.name}: olefile lists {sorted(listed)}")
        for name, data in expected.items():
            if ole.openstream(name).read() != data:
                raise SystemExit(f"{path.name}: olefile reads a different {name}")
        if any("vba" in name.lower() or "macros" in name.lower() for name in listed):
            raise SystemExit(f"{path.name}: carries a macro storage")


def check_encrypted(path: Path, package: bytes) -> None:
    with path.open("rb") as handle:
        office = msoffcrypto.OfficeFile(handle)
        if not office.is_encrypted():
            raise SystemExit(f"{path.name}: msoffcrypto-tool does not report encryption")
        office.load_key(password=PASSWORD)
        plain: io.BytesIO = io.BytesIO()
        office.decrypt(plain)
    if plain.getvalue() != package:
        raise SystemExit(f"{path.name}: decrypting does not return the authored package")


def main() -> int:
    doc, doc_streams = word_document()
    msg, msg_streams = outlook_message()
    package: bytes = wordprocessing_package()
    outputs: dict[str, bytes] = {
        "memo.doc": doc,
        "memo.msg": msg,
        "memo_encrypted.docx": encrypted_document(package),
    }
    for name, data in outputs.items():
        (HERE / name).write_bytes(data)
    check_streams(HERE / "memo.doc", doc_streams)
    check_streams(HERE / "memo.msg", msg_streams)
    check_encrypted(HERE / "memo_encrypted.docx", package)
    for name, data in outputs.items():
        sys.stdout.write(f"{name} sha256={hashlib.sha256(data).hexdigest()} bytes={len(data)}\n")
    sys.stdout.write(
        f"authored package sha256={hashlib.sha256(package).hexdigest()} bytes={len(package)}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
