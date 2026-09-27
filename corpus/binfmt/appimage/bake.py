import pathlib
import struct
import sys

PAYLOAD_OFFSET: int = 0x10_000
LOAD_ADDRESS: int = 0x40_0000


def bake(squashfs: bytes) -> bytes:
    total: int = PAYLOAD_OFFSET + len(squashfs)
    header: bytearray = bytearray(PAYLOAD_OFFSET)
    header[0:16] = b"\x7fELF\x02\x01\x01\x00AI\x02\x00\x00\x00\x00\x00"
    struct.pack_into("<HHIQQQIHHH", header, 16, 2, 62, 1, LOAD_ADDRESS, 64, 0, 0, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", header, 64, 1, 5, 0, LOAD_ADDRESS, 0, total, total, 0)
    return bytes(header) + squashfs


if __name__ == "__main__":
    here: pathlib.Path = pathlib.Path(__file__).resolve().parent
    squashfs: bytes = (here.parent / "squashfs" / "hello.squashfs").read_bytes()
    target: pathlib.Path = here / "hello.AppImage"
    target.write_bytes(bake(squashfs))
    sys.stdout.write(f"wrote {target.name}\n")
