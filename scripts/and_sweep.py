from __future__ import annotations

import re
import sys
from pathlib import Path


URL_PROTOCOL_RE: re.Pattern[str] = re.compile(r"(?:https?|ftp|git|ssh|file|mailto):", re.IGNORECASE)
HTML_ENTITY_RE: re.Pattern[str] = re.compile(r"&[a-zA-Z][a-zA-Z0-9]*;")
INLINE_CODE_RE: re.Pattern[str] = re.compile(r"`[^`]*`")
FENCED_CODE_RE: re.Pattern[str] = re.compile(r"```[\s\S]*?```", re.MULTILINE)
URL_RE: re.Pattern[str] = re.compile(r"\b(?:https?|ftp|git|ssh|file|mailto):[^\s<>'\")]+", re.IGNORECASE)
MD_LINK_URL_RE: re.Pattern[str] = re.compile(r"\]\([^)]*\)")

AND_TOKEN_RE: re.Pattern[str] = re.compile(r"(\s)(and|And|AND)(\s)")


def protect_segments(text: str) -> tuple[str, list[str]]:
    saved: list[str] = []

    def stash(m: re.Match[str]) -> str:
        saved.append(m.group(0))
        return f"\x00{len(saved) - 1}\x00"

    text = FENCED_CODE_RE.sub(stash, text)
    text = INLINE_CODE_RE.sub(stash, text)
    text = MD_LINK_URL_RE.sub(stash, text)
    text = URL_RE.sub(stash, text)
    return text, saved


def restore_segments(text: str, saved: list[str]) -> str:
    def restore(m: re.Match[str]) -> str:
        idx: int = int(m.group(1))
        return saved[idx]

    return re.sub(r"\x00(\d+)\x00", restore, text)


def sweep_markdown(text: str) -> str:
    body, saved = protect_segments(text)
    body = AND_TOKEN_RE.sub(lambda m: f"{m.group(1)}&{m.group(3)}", body)
    return restore_segments(body, saved)


def sweep_rust_strings(text: str) -> str:
    out: list[str] = []
    i: int = 0
    n: int = len(text)
    while i < n:
        c: str = text[i]
        if c == '"':
            j: int = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            seg: str = text[i:j]
            inner: str = seg[1:-1] if len(seg) >= 2 and seg.endswith('"') else seg[1:]
            if "://" in inner or HTML_ENTITY_RE.search(inner):
                out.append(seg)
            else:
                rewritten: str = AND_TOKEN_RE.sub(lambda m: f"{m.group(1)}&{m.group(3)}", inner)
                out.append('"' + rewritten + ('"' if seg.endswith('"') else ""))
            i = j
            continue
        if c == "/" and i + 2 < n and text[i + 1] == "/" and text[i + 2] == "/":
            j = i
            while j < n and text[j] != "\n":
                j += 1
            line: str = text[i:j]
            rewritten = AND_TOKEN_RE.sub(lambda m: f"{m.group(1)}&{m.group(3)}", line)
            out.append(rewritten)
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: and_sweep.py <mode: md|rs> <file> [file...]", file=sys.stderr)
        return 2
    mode: str = sys.argv[1]
    rc: int = 0
    for arg in sys.argv[2:]:
        p: Path = Path(arg)
        if not p.is_file():
            print(f"skip (not a file): {p}", file=sys.stderr)
            continue
        src: str = p.read_text(encoding="utf-8")
        if mode == "md":
            dst: str = sweep_markdown(src)
        elif mode == "rs":
            dst = sweep_rust_strings(src)
        else:
            print(f"unknown mode: {mode}", file=sys.stderr)
            return 2
        if dst != src:
            p.write_text(dst, encoding="utf-8")
            print(f"changed: {p}")
        else:
            print(f"clean:   {p}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
