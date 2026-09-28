"""Write the fail-closed pickle fixtures and their provenance.toml.

Run: python generate.py   (from this directory, CPython 3.11 or newer)

Every stream is assembled opcode by opcode, so no real callable is referenced
while writing, and the output is byte-identical on every host. The requested
callables recorded in provenance.toml come from find_class_harness.py, which
loads each fixture with a recording find_class that returns inert stubs.
"""

from __future__ import annotations

import hashlib
import io
import pickle
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT: Path = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))

from find_class_harness import examine

TORCH_MAGIC: int = 0x1950A86A20F9469CFC6C
PROTO2: bytes = b"\x80\x02"
PROTO4: bytes = b"\x80\x04"
MARK: bytes = b"("
TUPLE: bytes = b"t"
REDUCE: bytes = b"R"
STOP: bytes = b"."


@dataclass(frozen=True)
class Fixture:
    file: str
    shape: str
    data: bytes
    pickle_offsets: list[int] = field(default_factory=list)


def text_global(module: str, name: str) -> bytes:
    return b"c" + module.encode("ascii") + b"\n" + name.encode("ascii") + b"\n"


def short_unicode(text: str) -> bytes:
    raw: bytes = text.encode("utf-8")
    return b"\x8c" + bytes([len(raw)]) + raw


def stack_global(module: str, name: str) -> bytes:
    return short_unicode(module) + short_unicode(name) + b"\x93"


def short_bytes(raw: bytes) -> bytes:
    return b"C" + bytes([len(raw)]) + raw


def text_unicode(text: str) -> bytes:
    return b"V" + text.encode("ascii") + b"\n"


def small_int(value: int) -> bytes:
    return b"K" + bytes([value])


def call_p2(module: str, name: str, args: bytes) -> bytes:
    return PROTO2 + text_global(module, name) + MARK + args + TUPLE + REDUCE + STOP


def call_p4(module: str, name: str, args: bytes) -> bytes:
    return PROTO4 + stack_global(module, name) + MARK + args + TUPLE + REDUCE + STOP


def protocol0_call(prefix: bytes, module: str, name: str, arg: str) -> bytes:
    return prefix + text_global(module, name) + MARK + text_unicode(arg) + TUPLE + REDUCE + STOP


def stored_zip(members: list[tuple[str, bytes]]) -> bytes:
    buffer: io.BytesIO = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in members:
            info: zipfile.ZipInfo = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)
    return buffer.getvalue()


def fixtures() -> list[Fixture]:
    magic: bytes = pickle.dumps(TORCH_MAGIC, protocol=2)
    nested_global: bytes = protocol0_call(b"", "os", "system", "echo nested")
    nested_unicode_first: bytes = protocol0_call(text_unicode("weights") + b"0", "os", "system", "echo nested")
    zip_first: bytes = stored_zip([("config.json", b'{"layers": 2}\n')])
    zip_payload: bytes = call_p2("os", "system", short_unicode("echo polyglot"))
    memo_free_dict: bytes = (
        PROTO4 + b"}" + MARK + short_unicode("model") + short_unicode("tiny") + short_unicode("layers") + small_int(2) + b"u" + STOP
    )
    return [
        Fixture("stacked_streams.pkl", "a benign magic-number stream, then a stream that calls os.system", magic + call_p2("os", "system", short_unicode("echo stacked"))),
        Fixture(
            "stacked_protocol0_stream.pkl",
            "a benign magic-number stream, then a protocol-0 stream that starts with a UNICODE opcode and calls os.system",
            magic + protocol0_call(text_unicode("header") + b"0", "os", "system", "echo stacked"),
        ),
        Fixture(
            "nested_global_first.pkl",
            "a protocol-4 dict whose bytes value is a protocol-0 pickle without PROTO that starts with GLOBAL os.system",
            PROTO4 + b"}" + short_unicode("weights") + short_bytes(nested_global) + b"s" + STOP,
        ),
        Fixture(
            "nested_unicode_first.pkl",
            "a protocol-4 dict whose bytes value is a pickle without PROTO that starts with a UNICODE opcode and calls os.system",
            PROTO4 + b"}" + short_unicode("weights") + short_bytes(nested_unicode_first) + b"s" + STOP,
        ),
        Fixture("call_os_execl.pkl", "os.execl('/bin/true', 'true')", call_p2("os", "execl", short_unicode("/bin/true") + short_unicode("true"))),
        Fixture("call_os_spawnlp.pkl", "os.spawnlp(0, 'true', 'true')", call_p4("os", "spawnlp", small_int(0) + short_unicode("true") + short_unicode("true"))),
        Fixture(
            "call_os_posix_spawn.pkl",
            "os.posix_spawn('/bin/true', ['true'], {})",
            call_p4("os", "posix_spawn", short_unicode("/bin/true") + b"]" + short_unicode("true") + b"a" + b"}"),
        ),
        Fixture("call_os_startfile.pkl", "os.startfile('notes.txt')", call_p2("os", "startfile", short_unicode("notes.txt"))),
        Fixture(
            "call_urllib_request_urlopen.pkl",
            "urllib.request.urlopen('http://127.0.0.1:9/')",
            call_p4("urllib.request", "urlopen", short_unicode("http://127.0.0.1:9/")),
        ),
        Fixture("call_timeit_timeit.pkl", "timeit.timeit('pass')", call_p2("timeit", "timeit", short_unicode("pass"))),
        Fixture("call_cprofile_run.pkl", "cProfile.run('pass')", call_p4("cProfile", "run", short_unicode("pass"))),
        Fixture("call_pdb_run.pkl", "pdb.run('pass')", call_p2("pdb", "run", short_unicode("pass"))),
        Fixture(
            "pickle_then_zip.pkl",
            "a memo-free protocol-4 dict pickle followed by a stored zip holding data/weights.txt",
            memo_free_dict + stored_zip([("data/weights.txt", b"0.5 0.25\n")]),
        ),
        Fixture(
            "zip_then_pickle.zip",
            "a stored zip holding config.json followed by a protocol-2 pickle that calls os.system",
            zip_first + zip_payload,
            [len(zip_first)],
        ),
    ]


def toml_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    lines: list[str] = [
        'schema = "disrobe.fixture.provenance/v1"',
        'source = "self-authored"',
        'generator = "python generate.py"',
        'reference = "python find_class_harness.py <this directory>"',
        f'python = {toml_string(sys.version.split()[0])}',
    ]
    for fixture in fixtures():
        path: Path = ROOT / fixture.file
        path.write_bytes(fixture.data)
        truth: dict[str, Any] = examine(path, fixture.pickle_offsets)
        lines.append("")
        lines.append("[[fixtures]]")
        lines.append(f"file = {toml_string(fixture.file)}")
        lines.append(f"sha256 = {toml_string(hashlib.sha256(fixture.data).hexdigest())}")
        lines.append(f"size = {len(fixture.data)}")
        lines.append(f"shape = {toml_string(fixture.shape)}")
        if fixture.pickle_offsets:
            lines.append(f"pickle_offsets = [{', '.join(str(offset) for offset in fixture.pickle_offsets)}]")
        requested: list[str] = list(truth["requested"])
        lines.append(f"requested = [{', '.join(toml_string(name) for name in requested)}]")
    (ROOT / "provenance.toml").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
