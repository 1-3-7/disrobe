from __future__ import annotations

import base64
import bz2
import json
import lzma
import marshal
import sys
import zlib
from pathlib import Path

APP_SOURCE: str = (
    "def greet(name):\n"
    "    return \"hello, \" + name\n"
    "\n"
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "def main():\n"
    "    total = 0\n"
    "    for i in range(5):\n"
    "        total = total + i\n"
    "    return total\n"
    "\n"
    "print(add(greet(\"x\"), \"y\"))\n"
    "print(main())\n"
)


def rc4(data: bytes, key: bytes) -> bytes:
    state: list[int] = list(range(256))
    j: int = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    out: bytearray = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) % 256])
    return bytes(out)


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


BASE91_ALPHABET: bytes = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    b"0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)


def base91_encode(data: bytes) -> bytes:
    out: bytearray = bytearray()
    accumulator: int = 0
    bits: int = 0
    for byte in data:
        accumulator |= byte << bits
        bits += 8
        if bits > 13:
            value: int = accumulator & 8191
            if value > 88:
                accumulator >>= 13
                bits -= 13
            else:
                value = accumulator & 16383
                accumulator >>= 14
                bits -= 14
            out.append(BASE91_ALPHABET[value % 91])
            out.append(BASE91_ALPHABET[value // 91])
    if bits > 0:
        out.append(BASE91_ALPHABET[accumulator % 91])
        if bits > 7 or accumulator > 90:
            out.append(BASE91_ALPHABET[accumulator // 91])
    return bytes(out)


BASE45_ALPHABET: bytes = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def base45_encode(data: bytes) -> bytes:
    out: bytearray = bytearray()
    for i in range(0, len(data) - 1, 2):
        value: int = (data[i] << 8) | data[i + 1]
        out.append(BASE45_ALPHABET[value % 45])
        out.append(BASE45_ALPHABET[(value // 45) % 45])
        out.append(BASE45_ALPHABET[value // 2025])
    if len(data) % 2 == 1:
        value = data[-1]
        out.append(BASE45_ALPHABET[value % 45])
        out.append(BASE45_ALPHABET[value // 45])
    return bytes(out)


def ascii85_encode(data: bytes) -> bytes:
    out: bytearray = bytearray()
    for i in range(0, len(data), 4):
        chunk: bytes = data[i : i + 4]
        pad: int = 4 - len(chunk)
        chunk = chunk + b"\x00" * pad
        acc: int = int.from_bytes(chunk, "big")
        group: bytearray = bytearray(5)
        for k in range(4, -1, -1):
            group[k] = 33 + (acc % 85)
            acc //= 85
        out.extend(group[: 5 - pad])
    return bytes(out)


def percent_encode(data: bytes) -> bytes:
    unreserved: set[int] = set(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
    )
    out: bytearray = bytearray()
    for byte in data:
        if byte in unreserved:
            out.append(byte)
        else:
            out.extend(f"%{byte:02X}".encode("ascii"))
    return bytes(out)


TEA_DELTA: int = 0x9E3779B9
MASK32: int = 0xFFFFFFFF


def _key_words(key: bytes) -> list[int]:
    return [int.from_bytes(key[i : i + 4], "little") for i in range(0, 16, 4)]


def tea_encrypt_block(v0: int, v1: int, k: list[int]) -> tuple[int, int]:
    total: int = 0
    for _ in range(32):
        total = (total + TEA_DELTA) & MASK32
        v0 = (
            v0
            + (
                ((v1 << 4) + k[0])
                ^ (v1 + total)
                ^ ((v1 >> 5) + k[1])
            )
        ) & MASK32
        v1 = (
            v1
            + (
                ((v0 << 4) + k[2])
                ^ (v0 + total)
                ^ ((v0 >> 5) + k[3])
            )
        ) & MASK32
    return v0, v1


def xtea_encrypt_block(v0: int, v1: int, k: list[int]) -> tuple[int, int]:
    total: int = 0
    for _ in range(32):
        v0 = (
            v0
            + (
                (((v1 << 4) ^ (v1 >> 5)) + v1)
                ^ (total + k[total & 3])
            )
        ) & MASK32
        total = (total + TEA_DELTA) & MASK32
        v1 = (
            v1
            + (
                (((v0 << 4) ^ (v0 >> 5)) + v0)
                ^ (total + k[(total >> 11) & 3])
            )
        ) & MASK32
    return v0, v1


def tea_family_encrypt(data: bytes, key: bytes, variant: str) -> bytes:
    if len(data) % 8 != 0:
        data = data + b"\x00" * (8 - len(data) % 8)
    k: list[int] = _key_words(key)
    out: bytearray = bytearray()
    block = tea_encrypt_block if variant == "tea" else xtea_encrypt_block
    for i in range(0, len(data), 8):
        v0: int = int.from_bytes(data[i : i + 4], "little")
        v1: int = int.from_bytes(data[i + 4 : i + 8], "little")
        c0, c1 = block(v0, v1, k)
        out.extend(c0.to_bytes(4, "little"))
        out.extend(c1.to_bytes(4, "little"))
    return bytes(out)


def _xxtea_mx(total: int, y: int, z: int, p: int, e: int, k: list[int]) -> int:
    return (
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
    ) & MASK32


def xxtea_encrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % 4 != 0:
        data = data + b"\x00" * (4 - len(data) % 4)
    v: list[int] = [
        int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)
    ]
    n: int = len(v)
    k: list[int] = _key_words(key)
    rounds: int = 6 + 52 // n
    total: int = 0
    z: int = v[n - 1]
    for _ in range(rounds):
        total = (total + TEA_DELTA) & MASK32
        e: int = (total >> 2) & 3
        for p in range(n - 1):
            y: int = v[p + 1]
            v[p] = (v[p] + _xxtea_mx(total, y, z, p, e, k)) & MASK32
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + _xxtea_mx(total, y, z, n - 1, e, k)) & MASK32
        z = v[n - 1]
    out: bytearray = bytearray()
    for word in v:
        out.extend(word.to_bytes(4, "little"))
    return bytes(out)


SIGMA: bytes = b"expand 32-byte k"


def _rotl(value: int, count: int) -> int:
    value &= MASK32
    return ((value << count) | (value >> (32 - count))) & MASK32


def _chacha_quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def _chacha_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    const: list[int] = [
        int.from_bytes(SIGMA[i : i + 4], "little") for i in range(0, 16, 4)
    ]
    key_words: list[int] = [
        int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)
    ]
    nonce_words: list[int] = [
        int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)
    ]
    state: list[int] = const + key_words + [counter & MASK32] + nonce_words
    working: list[int] = list(state)
    for _ in range(10):
        _chacha_quarter(working, 0, 4, 8, 12)
        _chacha_quarter(working, 1, 5, 9, 13)
        _chacha_quarter(working, 2, 6, 10, 14)
        _chacha_quarter(working, 3, 7, 11, 15)
        _chacha_quarter(working, 0, 5, 10, 15)
        _chacha_quarter(working, 1, 6, 11, 12)
        _chacha_quarter(working, 2, 7, 8, 13)
        _chacha_quarter(working, 3, 4, 9, 14)
    out: bytearray = bytearray()
    for i in range(16):
        out.extend(((working[i] + state[i]) & MASK32).to_bytes(4, "little"))
    return bytes(out)


def chacha20_apply(data: bytes, key: bytes, nonce: bytes, counter: int) -> bytes:
    out: bytearray = bytearray()
    for block_index, i in enumerate(range(0, len(data), 64)):
        keystream: bytes = _chacha_block(key, nonce, counter + block_index)
        chunk: bytes = data[i : i + 64]
        out.extend(b ^ keystream[j] for j, b in enumerate(chunk))
    return bytes(out)


def _salsa_quarter(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[b] ^= _rotl((state[a] + state[d]) & MASK32, 7)
    state[c] ^= _rotl((state[b] + state[a]) & MASK32, 9)
    state[d] ^= _rotl((state[c] + state[b]) & MASK32, 13)
    state[a] ^= _rotl((state[d] + state[c]) & MASK32, 18)


def _salsa_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    def word(buf: bytes, idx: int) -> int:
        return int.from_bytes(buf[idx : idx + 4], "little")

    state: list[int] = [0] * 16
    state[0] = word(SIGMA, 0)
    state[5] = word(SIGMA, 4)
    state[10] = word(SIGMA, 8)
    state[15] = word(SIGMA, 12)
    for i in range(4):
        state[1 + i] = word(key, i * 4)
        state[11 + i] = word(key, 16 + i * 4)
    state[6] = word(nonce, 0)
    state[7] = word(nonce, 4)
    state[8] = counter & MASK32
    state[9] = (counter >> 32) & MASK32
    working: list[int] = list(state)
    for _ in range(10):
        _salsa_quarter(working, 0, 4, 8, 12)
        _salsa_quarter(working, 5, 9, 13, 1)
        _salsa_quarter(working, 10, 14, 2, 6)
        _salsa_quarter(working, 15, 3, 7, 11)
        _salsa_quarter(working, 0, 1, 2, 3)
        _salsa_quarter(working, 5, 6, 7, 4)
        _salsa_quarter(working, 10, 11, 8, 9)
        _salsa_quarter(working, 15, 12, 13, 14)
    out: bytearray = bytearray()
    for i in range(16):
        out.extend(((working[i] + state[i]) & MASK32).to_bytes(4, "little"))
    return bytes(out)


def salsa20_apply(data: bytes, key: bytes, nonce: bytes, counter: int) -> bytes:
    out: bytearray = bytearray()
    for block_index, i in enumerate(range(0, len(data), 64)):
        keystream: bytes = _salsa_block(key, nonce, counter + block_index)
        chunk: bytes = data[i : i + 64]
        out.extend(b ^ keystream[j] for j, b in enumerate(chunk))
    return bytes(out)


def marshal_blob(src: str) -> bytes:
    return marshal.dumps(compile(src, "<dropper>", "exec"))


def build(out_dir: Path) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    blob: bytes = marshal_blob(APP_SOURCE)
    cases: dict[str, bytes] = {}

    cases["base64"] = base64.b64encode(APP_SOURCE.encode())
    cases["base64_zlib"] = base64.b64encode(zlib.compress(APP_SOURCE.encode()))
    cases["base85_zlib_marshal"] = base64.b85encode(zlib.compress(blob))
    cases["base32"] = base64.b32encode(APP_SOURCE.encode())
    cases["lzma_marshal"] = lzma.compress(blob)
    cases["bz2_marshal"] = bz2.compress(blob)
    cases["marshal_bare"] = blob
    cases["marshal_zlib"] = zlib.compress(blob)

    cases["base91_zlib_marshal"] = base91_encode(zlib.compress(blob))
    cases["base45_zlib_marshal"] = base45_encode(zlib.compress(blob))
    cases["ascii85_zlib_marshal"] = ascii85_encode(zlib.compress(blob))
    cases["percent_zlib_marshal"] = percent_encode(zlib.compress(blob))
    cases["base91_source"] = base91_encode(APP_SOURCE.encode())

    tea_key: bytes = b"tea-16byte-key!!"
    tea_loader: str = (
        "import zlib, marshal\n"
        f"KEY = {tea_key!r}\n"
        f"PAYLOAD = {tea_family_encrypt(zlib.compress(blob), tea_key, 'tea')!r}\n"
        "exec(marshal.loads(zlib.decompress(PAYLOAD)))\n"
    )
    cases["tea_zlib_marshal_loader"] = tea_loader.encode()

    xtea_key: bytes = b"xtea-key-sixteen"
    xtea_loader: str = (
        "import zlib, marshal\n"
        f"KEY = {xtea_key!r}\n"
        f"PAYLOAD = {tea_family_encrypt(zlib.compress(blob), xtea_key, 'xtea')!r}\n"
        "exec(marshal.loads(zlib.decompress(PAYLOAD)))\n"
    )
    cases["xtea_zlib_marshal_loader"] = xtea_loader.encode()

    xxtea_key: bytes = b"xxtea-key-16byte"
    xxtea_loader: str = (
        "import zlib, marshal\n"
        f"KEY = {xxtea_key!r}\n"
        f"PAYLOAD = {xxtea_encrypt(zlib.compress(blob), xxtea_key)!r}\n"
        "exec(marshal.loads(zlib.decompress(PAYLOAD)))\n"
    )
    cases["xxtea_zlib_marshal_loader"] = xxtea_loader.encode()

    chacha_key: bytes = b"chacha20-256bit-key-thirty-two!!"
    chacha_nonce: bytes = b"nonce-12byte"
    chacha_loader: str = (
        "import zlib, marshal\n"
        f"KEY = {chacha_key!r}\n"
        f"NONCE = {chacha_nonce!r}\n"
        f"PAYLOAD = {chacha20_apply(zlib.compress(blob), chacha_key, chacha_nonce, 0)!r}\n"
        "exec(marshal.loads(zlib.decompress(PAYLOAD)))\n"
    )
    cases["chacha20_zlib_marshal_loader"] = chacha_loader.encode()

    salsa_key: bytes = b"salsa20-256bit-key-thirty-two!!!"
    salsa_nonce: bytes = b"nonce-08"
    salsa_loader: str = (
        "import zlib, marshal\n"
        f"KEY = {salsa_key!r}\n"
        f"NONCE = {salsa_nonce!r}\n"
        f"PAYLOAD = {salsa20_apply(zlib.compress(blob), salsa_key, salsa_nonce, 0)!r}\n"
        "exec(marshal.loads(zlib.decompress(PAYLOAD)))\n"
    )
    cases["salsa20_zlib_marshal_loader"] = salsa_loader.encode()

    single_key: bytes = bytes([0x5E])
    cases["xor1_base64_zlib_marshal"] = base64.b64encode(
        xor(zlib.compress(blob), single_key)
    )

    multi_key: bytes = b"sekret"
    multi_loader: str = (
        "import zlib\n"
        f"KEY = {multi_key!r}\n"
        f"PAYLOAD = {xor(lzma.compress(blob), multi_key)!r}\n"
        "exec(zlib)\n"
    )
    cases["xor_multi_lzma_marshal_loader"] = multi_loader.encode()

    rc4_key: bytes = b"rc4secretkey"
    rc4_loader: str = (
        "import zlib, marshal\n"
        f"KEY = {rc4_key!r}\n"
        f"PAYLOAD = {rc4(zlib.compress(blob), rc4_key)!r}\n"
        "exec(marshal.loads(zlib.decompress(PAYLOAD)))\n"
    )
    cases["rc4_zlib_marshal_loader"] = rc4_loader.encode()

    written: dict[str, str] = {}
    for name, data in cases.items():
        path: Path = out_dir / f"{name}.bin"
        path.write_bytes(data)
        written[name] = str(path)

    (out_dir / "app_source.py").write_text(APP_SOURCE, encoding="utf-8")
    written["app_source"] = str(out_dir / "app_source.py")
    return written


def normalize_code(code: object) -> object:
    return {
        "co_names": sorted(code.co_names),
        "co_varnames": list(code.co_varnames),
        "co_consts": [
            normalize_code(c) if hasattr(c, "co_code") else repr(c)
            for c in code.co_consts
        ],
        "co_argcount": code.co_argcount,
        "names": sorted(
            getattr(child, "co_name", "")
            for child in code.co_consts
            if hasattr(child, "co_code")
        ),
    }


def grade(original_path: str, recovered_path: str) -> dict[str, object]:
    original_src: str = Path(original_path).read_text(encoding="utf-8")
    recovered_src: str = Path(recovered_path).read_text(encoding="utf-8")
    try:
        orig_code: object = compile(original_src, "<orig>", "exec")
    except SyntaxError as exc:
        return {"equivalent": False, "reason": f"original failed to compile: {exc}"}
    try:
        rec_code: object = compile(recovered_src, "<rec>", "exec")
    except SyntaxError as exc:
        return {"equivalent": False, "reason": f"recovered failed to compile: {exc}"}

    orig_norm: object = normalize_code(orig_code)
    rec_norm: object = normalize_code(rec_code)
    equivalent: bool = orig_norm == rec_norm
    return {
        "equivalent": equivalent,
        "orig": orig_norm,
        "rec": rec_norm,
    }


def main() -> int:
    command: str = sys.argv[1]
    if command == "build":
        result: dict[str, str] = build(Path(sys.argv[2]))
        print(json.dumps(result))
        return 0
    if command == "grade":
        verdict: dict[str, object] = grade(sys.argv[2], sys.argv[3])
        print(json.dumps(verdict))
        return 0 if verdict.get("equivalent") else 1
    print(json.dumps({"error": f"unknown command {command}"}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
