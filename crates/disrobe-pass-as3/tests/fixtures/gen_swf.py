from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

ABC_MINOR: int = 16
ABC_MAJOR: int = 46


def u30(value: int) -> bytes:
    out: bytearray = bytearray()
    v: int = value & 0xFFFFFFFF
    while True:
        byte: int = v & 0x7F
        v >>= 7
        if v != 0:
            byte |= 0x80
        out.append(byte)
        if v == 0:
            break
    return bytes(out)


def s24(value: int) -> bytes:
    raw: int = value & 0xFFFFFF
    return bytes((raw & 0xFF, (raw >> 8) & 0xFF, (raw >> 16) & 0xFF))


class Pool:
    def __init__(self: "Pool", /) -> None:
        self.integers: list[int] = [0]
        self.strings: list[str] = [""]
        self.namespaces: list[tuple[int, int]] = [(0, 0)]
        self.multinames: list[tuple[int, int]] = [(0, 0)]

    def intern_string(self: "Pool", s: str, /) -> int:
        if s in self.strings:
            return self.strings.index(s)
        self.strings.append(s)
        return len(self.strings) - 1

    def intern_int(self: "Pool", v: int, /) -> int:
        if v in self.integers:
            return self.integers.index(v)
        self.integers.append(v)
        return len(self.integers) - 1

    def intern_ns(self: "Pool", kind: int, name: str, /) -> int:
        name_idx: int = self.intern_string(name)
        self.namespaces.append((kind, name_idx))
        return len(self.namespaces) - 1

    def intern_qname(self: "Pool", ns: int, name: str, /) -> int:
        name_idx: int = self.intern_string(name)
        self.multinames.append((ns, name_idx))
        return len(self.multinames) - 1

    def emit(self: "Pool", /) -> bytes:
        out: bytearray = bytearray()
        out += u30(len(self.integers))
        for v in self.integers[1:]:
            out += u30(v)
        out += u30(1)
        out += u30(1)
        out += u30(len(self.strings))
        for s in self.strings[1:]:
            raw: bytes = s.encode("utf-8")
            out += u30(len(raw))
            out += raw
        out += u30(len(self.namespaces))
        for kind, name_idx in self.namespaces[1:]:
            out.append(kind)
            out += u30(name_idx)
        out += u30(1)
        out += u30(len(self.multinames))
        for ns, name in self.multinames[1:]:
            out.append(0x07)
            out += u30(ns)
            out += u30(name)
        return bytes(out)


def emit_method_info(param_types: list[int], return_type: int, name: int) -> bytes:
    out: bytearray = bytearray()
    out += u30(len(param_types))
    out += u30(return_type)
    for p in param_types:
        out += u30(p)
    out += u30(name)
    out.append(0x00)
    return bytes(out)


def emit_body(method: int, max_stack: int, local_count: int, code: bytes) -> bytes:
    out: bytearray = bytearray()
    out += u30(method)
    out += u30(max_stack)
    out += u30(local_count)
    out += u30(1)
    out += u30(max(max_stack, 1))
    out += u30(len(code))
    out += code
    out += u30(0)
    out += u30(0)
    return bytes(out)


def build_abc() -> bytes:
    pool: Pool = Pool()
    pkg_ns: int = pool.intern_ns(0x16, "")
    class_mn: int = pool.intern_qname(pkg_ns, "Counter")
    obj_mn: int = pool.intern_qname(pkg_ns, "Object")
    sum_mn: int = pool.intern_qname(pkg_ns, "sumTo")
    total_mn: int = pool.intern_qname(pkg_ns, "total")

    code: bytearray = bytearray()
    code += b"\x24\x00"
    code += b"\xd6"
    code += b"\x10"
    entry_jump_operand: int = len(code)
    code += s24(0)
    after_entry_jump: int = len(code)

    top_off: int = len(code)
    code += b"\xd0"
    code += b"\xd2"
    code += b"\x61"
    code += u30(total_mn)
    code += b"\xc2\x02"

    test_off: int = len(code)
    code += b"\xd2"
    code += b"\xd1"
    code += b"\x0f"
    back_operand: int = len(code)
    code += s24(0)
    after_back: int = len(code)

    code += b"\xd0"
    code += b"\x66"
    code += u30(total_mn)
    code += b"\x48"

    def patch(at: int, after: int, target: int) -> None:
        rel: int = target - after
        raw: int = rel & 0xFFFFFF
        code[at] = raw & 0xFF
        code[at + 1] = (raw >> 8) & 0xFF
        code[at + 2] = (raw >> 16) & 0xFF

    patch(entry_jump_operand, after_entry_jump, test_off)
    patch(back_operand, after_back, top_off)

    b: bytearray = bytearray()
    b += struct.pack("<H", ABC_MINOR)
    b += struct.pack("<H", ABC_MAJOR)
    b += pool.emit()

    b += u30(2)
    b += emit_method_info([], 0, 0)
    b += emit_method_info([obj_mn], 0, sum_mn)

    b += u30(0)

    b += u30(1)
    b += u30(class_mn)
    b += u30(obj_mn)
    b.append(0x00)
    b += u30(0)
    b += u30(0)
    b += u30(2)
    b += u30(total_mn)
    b.append(0x00)
    b += u30(1)
    b += u30(0)
    b += u30(0)
    b += u30(sum_mn)
    b.append(0x01)
    b += u30(0)
    b += u30(1)

    b += u30(0)
    b += u30(0)

    b += u30(1)
    b += u30(0)
    b += u30(0)

    b += u30(2)
    b += emit_body(0, 1, 1, bytes([0x47]))
    b += emit_body(1, 3, 2, bytes(code))
    return bytes(b)


def pack_tag(code: int, payload: bytes) -> bytes:
    if len(payload) < 0x3F:
        header: int = (code << 6) | len(payload)
        return struct.pack("<H", header) + payload
    header = (code << 6) | 0x3F
    return struct.pack("<H", header) + struct.pack("<I", len(payload)) + payload


def build_swf(compression: str) -> bytes:
    abc: bytes = build_abc()
    do_abc_payload: bytes = struct.pack("<I", 1) + b"CounterScript" + b"\x00" + abc

    body: bytearray = bytearray()
    body.append(0x00)
    body += struct.pack("<H", 24)
    body += struct.pack("<H", 1)
    file_attributes: bytes = bytes([0x08, 0x00, 0x00, 0x00])
    body += pack_tag(69, file_attributes)
    symbol_class: bytes = struct.pack("<H", 1) + struct.pack("<H", 0) + b"Counter" + b"\x00"
    body += pack_tag(76, symbol_class)
    body += pack_tag(82, do_abc_payload)
    body += pack_tag(0, b"")

    payload_for_length: bytes = bytes(body)
    file_length: int = 8 + len(payload_for_length)

    out: bytearray = bytearray()
    if compression == "uncompressed":
        out += b"FWS"
        out.append(13)
        out += struct.pack("<I", file_length)
        out += payload_for_length
    elif compression == "zlib":
        out += b"CWS"
        out.append(13)
        out += struct.pack("<I", file_length)
        out += zlib.compress(payload_for_length, 9)
    else:
        raise ValueError(compression)
    return bytes(out)


def main() -> None:
    out_dir: Path = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "synthetic_counter_fws.swf").write_bytes(build_swf("uncompressed"))
    (out_dir / "synthetic_counter_cws.swf").write_bytes(build_swf("zlib"))
    print("wrote synthetic_counter_fws.swf and synthetic_counter_cws.swf")


if __name__ == "__main__":
    main()
