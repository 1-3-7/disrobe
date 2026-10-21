import pathlib
import sys

GOLDEN = 0x9E3779B9
SALT = 0x5A17C0DE
MASK = 0xFFFFFFFF


def xorshift(seed: int) -> int:
    seed ^= (seed << 13) & MASK
    seed ^= seed >> 17
    seed ^= (seed << 5) & MASK
    return seed & MASK


def encode(index: int, start: int, data: bytes) -> bytes:
    length = len(data)
    seed = (((index + 1) * GOLDEN) & MASK) ^ start ^ ((length << 12) & MASK) ^ (length >> 1) ^ SALT
    out = bytearray()
    for b in data:
        seed = xorshift(seed)
        masked = b ^ (((seed >> 8) ^ seed) & 0xFF)
        out.append(((masked >> 5) | (masked << 3)) & 0xFF)
    return bytes(out)


def main() -> int:
    here = pathlib.Path(sys.argv[1])
    plain = (here / "plain.txt").read_text(encoding="utf-8").splitlines()
    offsets = [0]
    blob = bytearray()
    for index, text in enumerate(plain):
        data = text.encode("utf-8")
        blob += encode(index, offsets[-1], data)
        offsets.append(offsets[-1] + len(data))
    offsets_literal = ", ".join(str(value) for value in offsets)
    blob_lines = []
    for at in range(0, len(blob), 16):
        blob_lines.append("            " + ", ".join(f"0x{b:02X}" for b in blob[at:at + 16]) + ",")
    source = (here / "Program.cs").read_text(encoding="utf-8")
    begin = source.index("        private static readonly int[] Offsets =")
    end = source.index("        [MethodImpl(MethodImplOptions.NoInlining)]", begin)
    generated = (
        "        private static readonly int[] Offsets = { " + offsets_literal + " };\n\n"
        "        private static readonly byte[] Blob =\n        {\n" + "\n".join(blob_lines) + "\n        };\n\n"
    )
    (here / "Program.cs").write_text(source[:begin] + generated + source[end:], encoding="utf-8", newline="\n")
    print(f"{len(plain)} strings, {len(blob)} blob bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
