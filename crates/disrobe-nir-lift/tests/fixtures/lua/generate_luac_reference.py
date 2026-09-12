from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

FIXTURE_DIR: Path = Path(__file__).resolve().parent
CRATE_DIR: Path = FIXTURE_DIR.parents[2]
WORKSPACE_DIR: Path = CRATE_DIR.parents[1]
CORPUS_DIR: Path = WORKSPACE_DIR / "corpus" / "lua"

TOOL_TIMEOUT_SECONDS: float = 120.0
DOWNLOAD_TIMEOUT_SECONDS: float = 120.0


@dataclass(frozen=True)
class Band:
    suffix: str
    tool: str
    tool_version: str
    release: str
    tarball_sha256: str
    opnames_member: str
    compiled_here: bool


BANDS: tuple[Band, ...] = (
    Band(
        suffix="5_1",
        tool="luac5.1",
        tool_version="Lua 5.1.5",
        release="5.1.5",
        tarball_sha256="2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333",
        opnames_member="src/lopcodes.c",
        compiled_here=True,
    ),
    Band(
        suffix="5_3",
        tool="luac5.3",
        tool_version="Lua 5.3.6",
        release="5.3.6",
        tarball_sha256="fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60",
        opnames_member="src/lopcodes.c",
        compiled_here=False,
    ),
    Band(
        suffix="5_4",
        tool="luac5.4",
        tool_version="Lua 5.4.8",
        release="5.4.8",
        tarball_sha256="4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
        opnames_member="src/lopnames.h",
        compiled_here=False,
    ),
)

SOURCES: tuple[tuple[str, Path], ...] = (
    ("hello", CORPUS_DIR / "baseline" / "hello.lua"),
    ("edge_cases", CORPUS_DIR / "megafile" / "edge_cases.lua"),
)

INSTRUCTION_LINE: re.Pattern[str] = re.compile(
    r"^\s*(?P<index>\d+)\s+\[[-\d]+\]\s+(?P<mnemonic>[A-Z][A-Z0-9]*)"
)
FUNCTION_LINE: re.Pattern[str] = re.compile(r"^(main|function) <")
QUOTED_NAME: re.Pattern[str] = re.compile(r"\"([A-Z][A-Z0-9]*)\"")


def sha256_of(path: Path, /) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_tool(name: str, /) -> str:
    located: str | None = shutil.which(name)
    if located is None:
        raise SystemExit(f"{name} is required to regenerate the reference and is not on PATH")
    return located


def run_tool(command: list[str], /, *, cwd: Path) -> str:
    completed: subprocess.CompletedProcess[str] = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=TOOL_TIMEOUT_SECONDS,
        check=True,
    )
    return completed.stdout


def check_tool_version(band: Band, /) -> None:
    completed: subprocess.CompletedProcess[str] = subprocess.run(
        [resolve_tool(band.tool), "-v"],
        capture_output=True,
        text=True,
        timeout=TOOL_TIMEOUT_SECONDS,
        check=False,
    )
    banner: str = completed.stdout + completed.stderr
    if band.tool_version not in banner:
        raise SystemExit(f"{band.tool} must report {band.tool_version}, reported {banner.strip()}")


def listing_to_mnemonics(listing: str, /) -> list[str]:
    lines: list[str] = []
    seen_function: bool = False
    function_index: int = 0
    for raw in listing.splitlines():
        if FUNCTION_LINE.match(raw):
            lines.append(f"function {function_index}")
            function_index += 1
            seen_function = True
            continue
        if not seen_function:
            continue
        matched: re.Match[str] | None = INSTRUCTION_LINE.match(raw)
        if matched is None:
            continue
        lines.append(matched.group("mnemonic"))
    if not lines:
        raise SystemExit("the reference listing decoded no instructions")
    return lines


def download_tarball(band: Band, cache: Path, /) -> Path:
    target: Path = cache / f"lua-{band.release}.tar.gz"
    if not target.exists():
        url: str = f"https://www.lua.org/ftp/lua-{band.release}.tar.gz"
        with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            target.write_bytes(response.read())
    observed: str = sha256_of(target)
    if observed != band.tarball_sha256:
        raise SystemExit(
            f"lua-{band.release}.tar.gz sha256 {observed} does not match the pinned {band.tarball_sha256}"
        )
    return target


def opcode_space(band: Band, tarball: Path, /) -> tuple[list[str], str]:
    member: str = f"lua-{band.release}/{band.opnames_member}"
    with tarfile.open(tarball, mode="r:gz") as archive:
        extracted = archive.extractfile(member)
        if extracted is None:
            raise SystemExit(f"{member} missing from lua-{band.release}.tar.gz")
        raw: bytes = extracted.read()
    text: str = raw.decode("utf-8")
    digest: str = hashlib.sha256(raw).hexdigest()
    start: int = text.find("opnames[")
    if start < 0:
        raise SystemExit(f"{member} does not define an opcode name table")
    end: int = text.find("NULL", start)
    if end < 0:
        raise SystemExit(f"{member} opcode name table has no terminator")
    names: list[str] = QUOTED_NAME.findall(text[start:end])
    if not names:
        raise SystemExit(f"{member} opcode name table is empty")
    return names, digest


def compile_chunk(band: Band, stem: str, source: Path, scratch: Path, /) -> Path:
    staged: Path = scratch / f"{stem}.lua"
    staged.write_bytes(source.read_bytes())
    output: str = f"{stem}.{band.suffix}.luac"
    run_tool([resolve_tool(band.tool), "-o", output, staged.name], cwd=scratch)
    produced: Path = scratch / output
    target: Path = FIXTURE_DIR / output
    target.write_bytes(produced.read_bytes())
    return target


def graded_chunk(band: Band, stem: str, /) -> Path:
    return CORPUS_DIR / "luac" / f"{stem}.{band.suffix}.luac"


def graded_entries(band: Band, /) -> list[tuple[str, Path | None]]:
    entries: list[tuple[str, Path | None]] = [
        (stem, source if band.compiled_here else None) for stem, source in SOURCES
    ]
    entries.append(("forms", FIXTURE_DIR / f"forms.{band.suffix}.lua"))
    return entries


def main() -> int:
    records: list[str] = []
    with tempfile.TemporaryDirectory() as raw_scratch:
        scratch: Path = Path(raw_scratch)
        cache: Path = scratch / "cache"
        cache.mkdir()
        for band in BANDS:
            check_tool_version(band)
            tarball: Path = download_tarball(band, cache)
            names, member_digest = opcode_space(band, tarball)
            space_path: Path = FIXTURE_DIR / f"opcode_space.{band.suffix}.txt"
            space_path.write_text("\n".join(names) + "\n", encoding="utf-8", newline="\n")
            records.append(
                f"- `{space_path.name}`: {len(names)} names from `lua-{band.release}/{band.opnames_member}`"
                f" (sha256 `{member_digest}`), file sha256 `{sha256_of(space_path)}`"
            )
            for stem, source in graded_entries(band):
                chunk: Path = (
                    graded_chunk(band, stem)
                    if source is None
                    else compile_chunk(band, stem, source, scratch)
                )
                listing: str = run_tool(
                    [resolve_tool(band.tool), "-p", "-l", str(chunk)], cwd=scratch
                )
                mnemonics: list[str] = listing_to_mnemonics(listing)
                out_path: Path = FIXTURE_DIR / f"{stem}.{band.suffix}.mnemonics"
                out_path.write_text(
                    "\n".join(mnemonics) + "\n", encoding="utf-8", newline="\n"
                )
                origin: str = (
                    "corpus/lua/luac"
                    if source is None
                    else f"`{source.name}` (sha256 `{sha256_of(source)}`) compiled here to"
                )
                records.append(
                    f"- `{out_path.name}`: {band.tool_version} `-p -l` over {origin} `{chunk.name}`"
                    f" (sha256 `{sha256_of(chunk)}`), file sha256 `{sha256_of(out_path)}`"
                )
    for record in records:
        print(record)
    return 0


if __name__ == "__main__":
    sys.exit(main())
