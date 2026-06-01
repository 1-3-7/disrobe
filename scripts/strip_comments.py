"""Strip non-rustdoc comments from .rs files.

Preserves: /// , //! , #[doc = "..."], // SAFETY:, // TODO:, // FIXME:, // HACK:
Removes:   // ... , /* ... */
Handles:   string / char / raw-string / byte-string literals.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_PRESERVE_RE: re.Pattern[str] = re.compile(r"^\s*(SAFETY\b|TODO\b|FIXME\b|HACK\b)")


@dataclass
class StripResult:
    new_text: str
    removed_line: int
    removed_block: int
    kept_doc_outer: int
    kept_doc_inner: int
    kept_safety: int
    kept_marker: int


def _classify_line_comment(body: str) -> str | None:
    """body = text after `//`, up to (but not including) the newline.

    Returns one of {"doc_outer", "doc_inner", "safety", "marker"} when preserved,
    None when the comment should be removed.
    """
    if body.startswith("/"):
        return "doc_outer"
    if body.startswith("!"):
        return "doc_inner"
    m: re.Match[str] | None = _PRESERVE_RE.match(body)
    if m is None:
        return None
    tag: str = m.group(1)
    if tag == "SAFETY":
        return "safety"
    return "marker"


def _is_raw_string_start(text: str, i: int) -> bool:
    j: int = i
    if text[j] == "b":
        j += 1
    if j >= len(text) or text[j] != "r":
        return False
    j += 1
    while j < len(text) and text[j] == "#":
        j += 1
    return j < len(text) and text[j] == '"'


def _consume_raw_string(text: str, i: int) -> int:
    """Return end index (exclusive) of the raw string literal starting at i."""
    j: int = i
    if text[j] == "b":
        j += 1
    j += 1
    hashes: int = 0
    while j < len(text) and text[j] == "#":
        hashes += 1
        j += 1
    j += 1
    closing: str = '"' + "#" * hashes
    end: int = text.find(closing, j)
    if end == -1:
        return len(text)
    return end + len(closing)


def _consume_string(text: str, i: int) -> int:
    """Standard double-quoted string starting at index i (text[i] == '\"')."""
    j: int = i + 1
    n: int = len(text)
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1
    return n


def _consume_char_or_lifetime(text: str, i: int) -> int:
    """text[i] == \"'\". Either a char literal or a lifetime token.

    Returns the index immediately after whatever we consumed."""
    n: int = len(text)
    j: int = i + 1
    if j >= n:
        return n
    if text[j] == "\\":
        k: int = j + 2
        while k < n and text[k] != "'":
            k += 1
            if k - j > 12:
                return i + 1
        if k < n:
            return k + 1
        return i + 1
    if j + 1 < n and text[j + 1] == "'":
        return j + 2
    return i + 1


def strip_file(text: str) -> StripResult:
    out: list[str] = []
    n: int = len(text)
    i: int = 0
    removed_line: int = 0
    removed_block: int = 0
    kept_doc_outer: int = 0
    kept_doc_inner: int = 0
    kept_safety: int = 0
    kept_marker: int = 0

    while i < n:
        c: str = text[i]

        if (c == "r" or (c == "b" and i + 1 < n and text[i + 1] == "r")) and _is_raw_string_start(
            text, i
        ):
            end: int = _consume_raw_string(text, i)
            out.append(text[i:end])
            i = end
            continue

        if c == "b" and i + 1 < n and text[i + 1] == '"':
            end = _consume_string(text, i + 1)
            out.append(text[i:end])
            i = end
            continue

        if c == "b" and i + 1 < n and text[i + 1] == "'":
            end = _consume_char_or_lifetime(text, i + 1)
            out.append(text[i:end])
            i = end
            continue

        if c == '"':
            end = _consume_string(text, i)
            out.append(text[i:end])
            i = end
            continue

        if c == "'":
            end = _consume_char_or_lifetime(text, i)
            out.append(text[i:end])
            i = end
            continue

        if c == "/" and i + 1 < n and text[i + 1] == "/":
            line_end: int = text.find("\n", i)
            if line_end == -1:
                line_end = n
            body: str = text[i + 2 : line_end]
            kind: str | None = _classify_line_comment(body)
            if kind is not None:
                if kind == "doc_outer":
                    kept_doc_outer += 1
                elif kind == "doc_inner":
                    kept_doc_inner += 1
                elif kind == "safety":
                    kept_safety += 1
                else:
                    kept_marker += 1
                out.append(text[i:line_end])
                i = line_end
                continue

            removed_line += 1
            line_start: int = _current_line_start(out)
            before: str = "".join(out)[line_start:] if line_start < len("".join(out)) else ""
            if before.strip() == "":
                del out[_index_for_pos(out, line_start) :]
                i = line_end + 1 if line_end < n else line_end
                continue
            while out and out[-1] and out[-1][-1] in " \t":
                trimmed: str = out[-1].rstrip(" \t")
                if trimmed == out[-1]:
                    break
                out[-1] = trimmed
                if trimmed == "":
                    out.pop()
            i = line_end
            continue

        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth: int = 1
            j: int = i + 2
            while j < n and depth > 0:
                if j + 1 < n and text[j] == "/" and text[j + 1] == "*":
                    depth += 1
                    j += 2
                    continue
                if j + 1 < n and text[j] == "*" and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                    continue
                j += 1
            removed_block += 1

            current_text: str = "".join(out)
            line_start = current_text.rfind("\n") + 1
            before = current_text[line_start:]
            if j < n and text[j] == "\n":
                after: str = ""
                after_consume: int = j + 1
            else:
                next_nl: int = text.find("\n", j)
                if next_nl == -1:
                    next_nl = n
                after = text[j:next_nl]
                after_consume = j

            if before.strip() == "" and after.strip() == "":
                drop: int = len(before)
                if drop > 0:
                    _trim_tail(out, drop)
                i = after_consume
                continue

            while out and out[-1] and out[-1][-1] in " \t":
                trimmed = out[-1].rstrip(" \t")
                if trimmed == out[-1]:
                    break
                out[-1] = trimmed
                if trimmed == "":
                    out.pop()
            i = j
            continue

        out.append(c)
        i += 1

    new_text: str = "".join(out)
    new_text = _collapse_excess_blank_lines(new_text)
    if not new_text.endswith("\n"):
        new_text += "\n"

    return StripResult(
        new_text=new_text,
        removed_line=removed_line,
        removed_block=removed_block,
        kept_doc_outer=kept_doc_outer,
        kept_doc_inner=kept_doc_inner,
        kept_safety=kept_safety,
        kept_marker=kept_marker,
    )


def _current_line_start(out: list[str]) -> int:
    s: str = "".join(out)
    nl: int = s.rfind("\n")
    return nl + 1 if nl != -1 else 0


def _index_for_pos(out: list[str], pos: int) -> int:
    running: int = 0
    for idx, chunk in enumerate(out):
        if running + len(chunk) > pos:
            return idx
        running += len(chunk)
    return len(out)


def _trim_tail(out: list[str], n_chars: int) -> None:
    while n_chars > 0 and out:
        last: str = out[-1]
        if len(last) <= n_chars:
            n_chars -= len(last)
            out.pop()
        else:
            out[-1] = last[:-n_chars]
            n_chars = 0


_BLANK_RUN_RE: re.Pattern[str] = re.compile(r"\n{4,}")


def _collapse_excess_blank_lines(text: str) -> str:
    return _BLANK_RUN_RE.sub("\n\n\n", text)


def iter_rs_files(roots: list[Path]) -> Iterator[Path]:
    for root in roots:
        if not root.exists():
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                if fn.endswith(".rs"):
                    yield Path(dirpath) / fn


def main() -> int:
    project_root: Path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    targets: list[Path] = [
        project_root / "crates",
        project_root / "bindings",
        project_root / "xtask",
        project_root / "fuzz",
    ]

    files_touched: int = 0
    total_removed_line: int = 0
    total_removed_block: int = 0
    total_doc_outer: int = 0
    total_doc_inner: int = 0
    total_safety: int = 0
    total_marker: int = 0
    anomalies: list[str] = []

    for path in iter_rs_files(targets):
        try:
            original: str = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            anomalies.append(f"{path}: non-utf8 ({e})")
            continue

        try:
            result: StripResult = strip_file(original)
        except Exception as e:
            anomalies.append(f"{path}: strip error {e!r}")
            continue

        total_doc_outer += result.kept_doc_outer
        total_doc_inner += result.kept_doc_inner
        total_safety += result.kept_safety
        total_marker += result.kept_marker

        if result.new_text != original:
            path.write_text(result.new_text, encoding="utf-8", newline="\n")
            files_touched += 1
            total_removed_line += result.removed_line
            total_removed_block += result.removed_block

    print(f"files_touched={files_touched}")
    print(f"removed_line={total_removed_line}")
    print(f"removed_block={total_removed_block}")
    print(f"kept_doc_outer={total_doc_outer}")
    print(f"kept_doc_inner={total_doc_inner}")
    print(f"kept_safety={total_safety}")
    print(f"kept_marker={total_marker}")
    if anomalies:
        print("ANOMALIES:")
        for a in anomalies:
            print(f"  {a}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
