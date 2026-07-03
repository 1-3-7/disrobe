import base64
import binascii
import marshal
import sys
import zlib
from pathlib import Path

CORPUS = Path(__file__).resolve().parent
ORIGINALS = CORPUS / "originals"
VARIANTS = CORPUS / "variants"


def py_bytes_literal(blob):
    out = ["b'"]
    for b in blob:
        if b == 0x5C:
            out.append("\\\\")
        elif b == 0x27:
            out.append("\\'")
        elif b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x09:
            out.append("\\t")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append("\\x%02x" % b)
    out.append("'")
    return "".join(out)


def build_variants(name, blob, tag):
    raw_b64 = base64.b64encode(blob).decode("ascii")
    zlib_blob = zlib.compress(blob, 9)
    zlib_b64 = base64.b64encode(zlib_blob).decode("ascii")
    hex_str = binascii.hexlify(blob).decode("ascii")
    lit = py_bytes_literal(blob)
    zlit = py_bytes_literal(zlib_blob)

    files = {}
    files["exec_plain"] = "import marshal\nexec(marshal.loads(%s))\n" % lit
    files["exec_zlib"] = (
        "import marshal, zlib\nexec(marshal.loads(zlib.decompress(%s)))\n" % zlit
    )
    files["exec_b64"] = (
        "import marshal, base64\n"
        "exec(marshal.loads(base64.b64decode('%s')))\n" % raw_b64
    )
    files["exec_b64_zlib"] = (
        "import marshal, base64, zlib\n"
        "exec(marshal.loads(zlib.decompress(base64.b64decode('%s'))))\n" % zlib_b64
    )
    files["exec_import_dunder"] = (
        "exec(__import__('marshal').loads(%s))\n" % lit
    )
    files["exec_hex"] = (
        "import marshal, binascii\n"
        "exec(marshal.loads(binascii.unhexlify('%s')))\n" % hex_str
    )
    written = []
    for variant, text in files.items():
        path = VARIANTS / ("%s.%s.%s.py" % (name, tag, variant))
        path.write_text(text, encoding="utf-8")
        written.append(path.name)
    bare = VARIANTS / ("%s.%s.bare.marshal" % (name, tag))
    bare.write_bytes(blob)
    written.append(bare.name)
    return written


def main():
    tag = "py%d%d" % (sys.version_info[0], sys.version_info[1])
    VARIANTS.mkdir(parents=True, exist_ok=True)
    all_written = []
    for src_path in sorted(ORIGINALS.glob("*.py")):
        name = src_path.stem
        source = src_path.read_text(encoding="utf-8")
        code = compile(source, "<%s>" % name, "exec")
        blob = marshal.dumps(code)
        all_written.extend(build_variants(name, blob, tag))
    for fname in all_written:
        print(fname)


if __name__ == "__main__":
    main()
