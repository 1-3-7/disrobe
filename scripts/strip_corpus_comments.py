from __future__ import annotations

import ast
import io
import os
import re
import sys
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


PRESERVE_PY_PREFIXES: tuple[str, ...] = (
    "!",
    "pyright:",
    "type:",
    "type :",
    "noqa",
    "pragma",
    "coding:",
    "coding=",
    "-*- coding",
    "fmt:",
    "fmt :",
    "isort:",
    "mypy:",
    "flake8:",
    "pylint:",
    "ruff:",
)

PRESERVE_JS_PREFIXES: tuple[str, ...] = (
    "eslint-disable",
    "eslint-enable",
    "@ts-",
    "@flow",
    "@noflow",
    "prettier-ignore",
    "biome-ignore",
    "@jsxImportSource",
    "@jsxRuntime",
    "@jsx",
    "@license",
    "@preserve",
    "@cc_on",
    "#__PURE__",
    "@__PURE__",
    "@vite-",
    "@bun",
    "@hermes",
    "@react-native",
    "@module",
    "#__NO_SIDE_EFFECTS__",
    "sourceMappingURL",
    "sourceURL",
    "<reference",
    "/<reference",
)

PRESERVE_GO_PREFIXES: tuple[str, ...] = (
    "go:",
    "+build",
    "go:build",
    "go:generate",
    "go:embed",
    "go:noinline",
    "go:nosplit",
    "go:linkname",
    "export ",
    "line ",
)

PRESERVE_RUST_LINE_PREFIXES: tuple[str, ...] = (
    "/",
    "!",
)

PRESERVE_PHP_PREFIXES: tuple[str, ...] = (
    "phpcs:",
    "@",
)

PRESERVE_RUBY_PREFIXES: tuple[str, ...] = (
    "frozen_string_literal",
    "encoding:",
    "encoding=",
    "coding:",
    "coding=",
    "-*-",
    "shareable_constant_value",
    "warn_indent",
    "typed:",
    "rubocop:",
)


@dataclass
class Stats:
    files_touched_by_lang: dict[str, int] = field(default_factory=dict)
    removed_by_lang: dict[str, int] = field(default_factory=dict)
    preserved_by_lang: dict[str, int] = field(default_factory=dict)
    skipped: list[tuple[Path, str]] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)

    def bump_touched(self, lang: str) -> None:
        self.files_touched_by_lang[lang] = self.files_touched_by_lang.get(lang, 0) + 1

    def add_removed(self, lang: str, n: int) -> None:
        self.removed_by_lang[lang] = self.removed_by_lang.get(lang, 0) + n

    def add_preserved(self, lang: str, n: int) -> None:
        self.preserved_by_lang[lang] = self.preserved_by_lang.get(lang, 0) + n


@dataclass
class StripOutcome:
    new_text: str
    removed: int
    preserved: int


def _normalize_line_endings(text: str) -> tuple[str, str]:
    if "\r\n" in text:
        return text.replace("\r\n", "\n"), "\r\n"
    if "\r" in text and "\n" not in text:
        return text.replace("\r", "\n"), "\r"
    return text, "\n"


def _restore_line_endings(text: str, original_eol: str) -> str:
    if original_eol == "\n":
        return text
    return text.replace("\n", original_eol)


_BLANK_RUN_RE: re.Pattern[str] = re.compile(r"\n{4,}")


def _collapse_runs_only(text: str) -> str:
    return _BLANK_RUN_RE.sub("\n\n\n", text)


def _matches_preserve(body: str, prefixes: tuple[str, ...]) -> bool:
    stripped: str = body.lstrip()
    return any(stripped.startswith(p) for p in prefixes)


def _is_shebang(text: str, i: int) -> bool:
    return i == 0 and text.startswith("#!")


def strip_python(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)

    try:
        tree: ast.Module = ast.parse(text_norm)
    except SyntaxError:
        return _strip_python_tokens_only(text, eol, has_ast=False)

    docstring_ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body: list[ast.stmt] = getattr(node, "body", [])
            if not body:
                continue
            first: ast.stmt = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                start: int = _lineno_col_to_offset(text_norm, first.lineno, first.col_offset)
                end_line: int = first.end_lineno or first.lineno
                end_col: int = first.end_col_offset or first.col_offset
                end: int = _lineno_col_to_offset(text_norm, end_line, end_col)
                docstring_ranges.append((start, end))

    docstring_ranges.sort()

    work: str = text_norm
    removed_docstrings: int = 0
    for start, end in reversed(docstring_ranges):
        line_start: int = work.rfind("\n", 0, start) + 1
        before_seg: str = work[line_start:start]
        if before_seg.strip() != "":
            continue
        line_end: int = work.find("\n", end)
        if line_end == -1:
            line_end = len(work)
        after_seg: str = work[end:line_end]
        if after_seg.strip() != "":
            continue
        work = work[:line_start] + work[line_end + 1 if line_end < len(work) else line_end :]
        removed_docstrings += 1

    token_outcome: StripOutcome = _strip_python_tokens_only(
        _restore_line_endings(work, eol), eol, has_ast=True
    )
    final_text: str = token_outcome.new_text
    return StripOutcome(
        new_text=final_text,
        removed=removed_docstrings + token_outcome.removed,
        preserved=token_outcome.preserved,
    )


def _lineno_col_to_offset(text: str, lineno: int, col: int) -> int:
    line_starts: list[int] = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)
    if lineno - 1 >= len(line_starts):
        return len(text)
    return line_starts[lineno - 1] + col


def _strip_python_tokens_only(text: str, eol: str, *, has_ast: bool) -> StripOutcome:
    text_norm: str
    text_norm, eol = _normalize_line_endings(text)

    try:
        tokens: list[tokenize.TokenInfo] = list(
            tokenize.tokenize(io.BytesIO(text_norm.encode("utf-8")).readline)
        )
    except (tokenize.TokenizeError, IndentationError, SyntaxError):
        return StripOutcome(new_text=text, removed=0, preserved=0)

    comment_tokens: list[tokenize.TokenInfo] = [t for t in tokens if t.type == tokenize.COMMENT]

    lines: list[str] = text_norm.split("\n")
    removed: int = 0
    preserved: int = 0

    deletions: list[tuple[int, int, int]] = []
    for tok in comment_tokens:
        srow: int = tok.start[0] - 1
        scol: int = tok.start[1]
        body: str = tok.string[1:]
        if srow == 0 and lines[0].startswith("#!"):
            preserved += 1
            continue
        if _matches_preserve(body, PRESERVE_PY_PREFIXES):
            preserved += 1
            continue
        ecol: int = tok.end[1]
        deletions.append((srow, scol, ecol))
        removed += 1

    deletions.sort(reverse=True)
    out_lines: list[str] = lines.copy()
    lines_to_drop: set[int] = set()
    for row, scol, ecol in deletions:
        line: str = out_lines[row]
        before: str = line[:scol]
        after: str = line[ecol:]
        if before.strip() == "" and after.strip() == "":
            lines_to_drop.add(row)
        else:
            out_lines[row] = (before + after).rstrip()

    final_lines: list[str] = [ln for idx, ln in enumerate(out_lines) if idx not in lines_to_drop]
    out_text: str = "\n".join(final_lines)
    out_text = _collapse_runs_only(out_text)
    if not out_text.endswith("\n"):
        out_text += "\n"

    return StripOutcome(
        new_text=_restore_line_endings(out_text, eol), removed=removed, preserved=preserved
    )


def _strip_c_family(
    text: str,
    *,
    preserve_line_prefixes: tuple[str, ...] = (),
    preserve_block_prefixes: tuple[str, ...] = (),
    rust_doc_mode: bool = False,
    line_token: str = "//",
    block_open: str = "/*",
    block_close: str = "*/",
    string_delims: tuple[str, ...] = ('"',),
    char_delims: tuple[str, ...] = ("'",),
    template_delim: str | None = None,
    backslash_continuation: bool = False,
) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)

    out: list[str] = []
    i: int = 0
    n: int = len(text_norm)
    removed: int = 0
    preserved: int = 0

    while i < n:
        c: str = text_norm[i]

        if _is_shebang(text_norm, i):
            line_end: int = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            out.append(text_norm[i:line_end])
            i = line_end
            continue

        if c in string_delims:
            j: int = i + 1
            while j < n:
                if text_norm[j] == "\\":
                    j += 2
                    continue
                if text_norm[j] == c:
                    j += 1
                    break
                j += 1
            out.append(text_norm[i:j])
            i = j
            continue

        if char_delims and c in char_delims:
            j = i + 1
            end: int = -1
            k: int = j
            while k < n and k < j + 8:
                if text_norm[k] == "\\":
                    k += 2
                    continue
                if text_norm[k] == c:
                    end = k + 1
                    break
                k += 1
            if end != -1:
                out.append(text_norm[i:end])
                i = end
                continue
            out.append(c)
            i += 1
            continue

        if template_delim and c == template_delim:
            j = i + 1
            depth: int = 0
            while j < n:
                if text_norm[j] == "\\":
                    j += 2
                    continue
                if text_norm[j] == "$" and j + 1 < n and text_norm[j + 1] == "{":
                    depth += 1
                    j += 2
                    continue
                if text_norm[j] == "}" and depth > 0:
                    depth -= 1
                    j += 1
                    continue
                if text_norm[j] == template_delim and depth == 0:
                    j += 1
                    break
                j += 1
            out.append(text_norm[i:j])
            i = j
            continue

        if line_token and text_norm.startswith(line_token, i):
            line_end = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            body: str = text_norm[i + len(line_token) : line_end]
            preserve_it: bool = False
            if rust_doc_mode:
                if body.startswith("/") or body.startswith("!"):
                    preserve_it = True
            if not preserve_it and _matches_preserve(body, preserve_line_prefixes):
                preserve_it = True
            if preserve_it:
                preserved += 1
                out.append(text_norm[i:line_end])
                i = line_end
                continue
            removed += 1
            line_start: int = text_norm.rfind("\n", 0, i) + 1
            before: str = text_norm[line_start:i]
            if before.strip() == "":
                while out and out[-1].endswith(before) and before:
                    out[-1] = out[-1][: -len(before)]
                    break
                if line_end < n:
                    i = line_end + 1
                else:
                    i = line_end
                continue
            out_str: str = "".join(out)
            stripped_before: str = before.rstrip()
            keep_to: int = line_start + len(stripped_before)
            cut_n: int = i - keep_to
            if cut_n > 0:
                if out and len(out[-1]) >= cut_n:
                    out[-1] = out[-1][:-cut_n]
                else:
                    accum: int = 0
                    while out and accum < cut_n:
                        seg: str = out[-1]
                        if len(seg) <= cut_n - accum:
                            accum += len(seg)
                            out.pop()
                        else:
                            out[-1] = seg[: -(cut_n - accum)]
                            accum = cut_n
            i = line_end
            continue

        if block_open and text_norm.startswith(block_open, i):
            body_start: int = i + len(block_open)
            close_at: int = text_norm.find(block_close, body_start)
            if close_at == -1:
                close_at = n
                block_end: int = n
            else:
                block_end = close_at + len(block_close)
            block_body: str = text_norm[body_start:close_at]
            preserve_it = False
            stripped_body: str = block_body.lstrip("*").lstrip()
            for pfx in preserve_block_prefixes:
                if stripped_body.startswith(pfx):
                    preserve_it = True
                    break
            if rust_doc_mode and block_body.startswith("*") and not block_body.startswith("**/"):
                preserve_it = True
            if preserve_it:
                preserved += 1
                out.append(text_norm[i:block_end])
                i = block_end
                continue
            removed += 1
            line_start = text_norm.rfind("\n", 0, i) + 1
            before = text_norm[line_start:i]
            after_line_end: int = text_norm.find("\n", block_end)
            if after_line_end == -1:
                after_line_end = n
            after: str = text_norm[block_end:after_line_end]
            if before.strip() == "" and after.strip() == "":
                cut_n2: int = i - line_start
                if cut_n2 > 0:
                    accum2: int = 0
                    while out and accum2 < cut_n2:
                        seg2: str = out[-1]
                        if len(seg2) <= cut_n2 - accum2:
                            accum2 += len(seg2)
                            out.pop()
                        else:
                            out[-1] = seg2[: -(cut_n2 - accum2)]
                            accum2 = cut_n2
                if after_line_end < n:
                    i = after_line_end + 1
                else:
                    i = after_line_end
                continue
            i = block_end
            continue

        out.append(c)
        i += 1

    new_text: str = "".join(out)
    new_text = _collapse_runs_only(new_text)
    if not new_text.endswith("\n"):
        new_text += "\n"

    return StripOutcome(
        new_text=_restore_line_endings(new_text, eol), removed=removed, preserved=preserved
    )


def strip_js_ts(text: str) -> StripOutcome:
    return _strip_c_family(
        text,
        preserve_line_prefixes=PRESERVE_JS_PREFIXES,
        preserve_block_prefixes=PRESERVE_JS_PREFIXES,
        string_delims=('"', "'"),
        char_delims=(),
        template_delim="`",
    )


def strip_go(text: str) -> StripOutcome:
    return _strip_c_family(
        text,
        preserve_line_prefixes=PRESERVE_GO_PREFIXES,
        preserve_block_prefixes=PRESERVE_GO_PREFIXES,
        string_delims=('"', "`"),
        char_delims=("'",),
    )


def strip_rust(text: str) -> StripOutcome:
    return _strip_c_family(
        text,
        preserve_line_prefixes=(),
        preserve_block_prefixes=(),
        rust_doc_mode=True,
        string_delims=('"',),
        char_delims=("'",),
    )


def strip_c_cpp(text: str) -> StripOutcome:
    return _strip_c_family(
        text,
        string_delims=('"',),
        char_delims=("'",),
    )


def strip_java_like(text: str) -> StripOutcome:
    return _strip_c_family(
        text,
        string_delims=('"',),
        char_delims=("'",),
    )


def strip_swift(text: str) -> StripOutcome:
    return _strip_c_family(
        text,
        string_delims=('"',),
        char_delims=(),
    )


def strip_kotlin_scala(text: str) -> StripOutcome:
    return _strip_c_family(
        text,
        string_delims=('"',),
        char_delims=("'",),
    )


def strip_php(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)

    out: list[str] = []
    i: int = 0
    n: int = len(text_norm)
    removed: int = 0
    preserved: int = 0
    in_php: bool = False

    while i < n:
        if not in_php:
            tag_open: int = text_norm.find("<?", i)
            if tag_open == -1:
                out.append(text_norm[i:])
                break
            out.append(text_norm[i:tag_open])
            if text_norm.startswith("<?php", tag_open):
                out.append("<?php")
                i = tag_open + 5
            elif text_norm.startswith("<?=", tag_open):
                out.append("<?=")
                i = tag_open + 3
            else:
                out.append("<?")
                i = tag_open + 2
            in_php = True
            continue

        c: str = text_norm[i]

        if text_norm.startswith("?>", i):
            out.append("?>")
            i += 2
            in_php = False
            continue

        if c in ('"', "'"):
            j: int = i + 1
            while j < n:
                if text_norm[j] == "\\":
                    j += 2
                    continue
                if text_norm[j] == c:
                    j += 1
                    break
                j += 1
            out.append(text_norm[i:j])
            i = j
            continue

        if c == "/" and i + 1 < n and text_norm[i + 1] == "/":
            line_end: int = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            body: str = text_norm[i + 2 : line_end]
            if _matches_preserve(body, PRESERVE_PHP_PREFIXES):
                preserved += 1
                out.append(text_norm[i:line_end])
                i = line_end
                continue
            removed += 1
            line_start: int = text_norm.rfind("\n", 0, i) + 1
            before: str = text_norm[line_start:i]
            if before.strip() == "":
                while out and out[-1].endswith(before) and before:
                    out[-1] = out[-1][: -len(before)]
                    break
                if line_end < n:
                    i = line_end + 1
                else:
                    i = line_end
                continue
            i = line_end
            continue

        if c == "#" and not (i + 1 < n and text_norm[i + 1] == "["):
            line_end = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            removed += 1
            line_start = text_norm.rfind("\n", 0, i) + 1
            before = text_norm[line_start:i]
            if before.strip() == "":
                while out and out[-1].endswith(before) and before:
                    out[-1] = out[-1][: -len(before)]
                    break
                if line_end < n:
                    i = line_end + 1
                else:
                    i = line_end
                continue
            i = line_end
            continue

        if c == "/" and i + 1 < n and text_norm[i + 1] == "*":
            close_at: int = text_norm.find("*/", i + 2)
            if close_at == -1:
                close_at = n
                block_end: int = n
            else:
                block_end = close_at + 2
            removed += 1
            line_start = text_norm.rfind("\n", 0, i) + 1
            before = text_norm[line_start:i]
            after_line_end: int = text_norm.find("\n", block_end)
            if after_line_end == -1:
                after_line_end = n
            after: str = text_norm[block_end:after_line_end]
            if before.strip() == "" and after.strip() == "":
                cut_n: int = i - line_start
                while out and cut_n > 0:
                    seg: str = out[-1]
                    if len(seg) <= cut_n:
                        cut_n -= len(seg)
                        out.pop()
                    else:
                        out[-1] = seg[:-cut_n]
                        cut_n = 0
                if after_line_end < n:
                    i = after_line_end + 1
                else:
                    i = after_line_end
                continue
            i = block_end
            continue

        out.append(c)
        i += 1

    new_text: str = "".join(out)
    new_text = _collapse_runs_only(new_text)
    if not new_text.endswith("\n"):
        new_text += "\n"

    return StripOutcome(
        new_text=_restore_line_endings(new_text, eol), removed=removed, preserved=preserved
    )


def strip_lua(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)

    out: list[str] = []
    i: int = 0
    n: int = len(text_norm)
    removed: int = 0
    preserved: int = 0

    while i < n:
        c: str = text_norm[i]

        if _is_shebang(text_norm, i):
            line_end: int = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            out.append(text_norm[i:line_end])
            i = line_end
            preserved += 1
            continue

        if c in ('"', "'"):
            j: int = i + 1
            while j < n:
                if text_norm[j] == "\\":
                    j += 2
                    continue
                if text_norm[j] == c:
                    j += 1
                    break
                if text_norm[j] == "\n":
                    break
                j += 1
            out.append(text_norm[i:j])
            i = j
            continue

        if c == "[" and i + 1 < n and text_norm[i + 1] in ("[", "="):
            eq_count: int = 0
            k: int = i + 1
            while k < n and text_norm[k] == "=":
                eq_count += 1
                k += 1
            if k < n and text_norm[k] == "[":
                close_str: str = "]" + "=" * eq_count + "]"
                end_at: int = text_norm.find(close_str, k + 1)
                if end_at == -1:
                    out.append(text_norm[i:])
                    i = n
                    continue
                out.append(text_norm[i : end_at + len(close_str)])
                i = end_at + len(close_str)
                continue

        if c == "-" and i + 1 < n and text_norm[i + 1] == "-":
            if i + 3 < n and text_norm[i + 2] == "[":
                eq_count = 0
                k = i + 3
                while k < n and text_norm[k] == "=":
                    eq_count += 1
                    k += 1
                if k < n and text_norm[k] == "[":
                    close_str = "]" + "=" * eq_count + "]"
                    end_at = text_norm.find(close_str, k + 1)
                    if end_at == -1:
                        end_at = n
                        block_end: int = n
                    else:
                        block_end = end_at + len(close_str)
                    removed += 1
                    line_start: int = text_norm.rfind("\n", 0, i) + 1
                    before: str = text_norm[line_start:i]
                    after_line_end: int = text_norm.find("\n", block_end)
                    if after_line_end == -1:
                        after_line_end = n
                    after: str = text_norm[block_end:after_line_end]
                    if before.strip() == "" and after.strip() == "":
                        cut_n: int = i - line_start
                        while out and cut_n > 0:
                            seg: str = out[-1]
                            if len(seg) <= cut_n:
                                cut_n -= len(seg)
                                out.pop()
                            else:
                                out[-1] = seg[:-cut_n]
                                cut_n = 0
                        if after_line_end < n:
                            i = after_line_end + 1
                        else:
                            i = after_line_end
                        continue
                    i = block_end
                    continue
            line_end = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            removed += 1
            line_start = text_norm.rfind("\n", 0, i) + 1
            before = text_norm[line_start:i]
            if before.strip() == "":
                while out and out[-1].endswith(before) and before:
                    out[-1] = out[-1][: -len(before)]
                    break
                if line_end < n:
                    i = line_end + 1
                else:
                    i = line_end
                continue
            i = line_end
            continue

        out.append(c)
        i += 1

    new_text: str = "".join(out)
    new_text = _collapse_runs_only(new_text)
    if not new_text.endswith("\n"):
        new_text += "\n"

    return StripOutcome(
        new_text=_restore_line_endings(new_text, eol), removed=removed, preserved=preserved
    )


def strip_ruby(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    lines: list[str] = text_norm.split("\n")
    out_lines: list[str] = []
    removed: int = 0
    preserved: int = 0
    in_block: bool = False

    for idx, line in enumerate(lines):
        if in_block:
            removed += 1
            if line.startswith("=end"):
                in_block = False
            continue
        if line.startswith("=begin"):
            in_block = True
            removed += 1
            continue
        if idx == 0 and line.startswith("#!"):
            out_lines.append(line)
            preserved += 1
            continue
        new_line: str = _strip_ruby_inline_hash(line)
        body: str = line.lstrip()
        if new_line == "" and body.startswith("#"):
            comment_body: str = body[1:].lstrip()
            if _matches_preserve(comment_body, PRESERVE_RUBY_PREFIXES):
                out_lines.append(line)
                preserved += 1
                continue
            removed += 1
            continue
        if new_line != line:
            removed += 1
            if new_line.strip() == "":
                continue
            out_lines.append(new_line.rstrip())
        else:
            out_lines.append(line)

    out_text: str = "\n".join(out_lines)
    out_text = _collapse_runs_only(out_text)
    if not out_text.endswith("\n"):
        out_text += "\n"
    return StripOutcome(
        new_text=_restore_line_endings(out_text, eol), removed=removed, preserved=preserved
    )


def _strip_ruby_inline_hash(line: str) -> str:
    i: int = 0
    n: int = len(line)
    in_str: str | None = None
    while i < n:
        c: str = line[i]
        if in_str is not None:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == "#":
            return line[:i].rstrip()
        i += 1
    return line


def strip_shell(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    lines: list[str] = text_norm.split("\n")
    out_lines: list[str] = []
    removed: int = 0
    preserved: int = 0

    for idx, line in enumerate(lines):
        if idx == 0 and line.startswith("#!"):
            out_lines.append(line)
            preserved += 1
            continue
        new_line: str = _strip_shell_inline_hash(line)
        body: str = line.lstrip()
        if new_line == "" and body.startswith("#"):
            comment_body: str = body[1:].lstrip()
            if comment_body.startswith("-*-") or comment_body.startswith("coding"):
                out_lines.append(line)
                preserved += 1
                continue
            removed += 1
            continue
        if new_line != line:
            removed += 1
            if new_line.strip() == "":
                continue
            out_lines.append(new_line.rstrip())
        else:
            out_lines.append(line)

    out_text: str = "\n".join(out_lines)
    out_text = _collapse_runs_only(out_text)
    if not out_text.endswith("\n"):
        out_text += "\n"
    return StripOutcome(
        new_text=_restore_line_endings(out_text, eol), removed=removed, preserved=preserved
    )


def _strip_shell_inline_hash(line: str) -> str:
    i: int = 0
    n: int = len(line)
    in_str: str | None = None
    while i < n:
        c: str = line[i]
        if in_str is not None:
            if c == "\\" and in_str == '"':
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == "#":
            if i == 0 or line[i - 1] in (" ", "\t"):
                return line[:i].rstrip()
        i += 1
    return line


def strip_powershell(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    out: list[str] = []
    i: int = 0
    n: int = len(text_norm)
    removed: int = 0
    preserved: int = 0

    while i < n:
        c: str = text_norm[i]

        if c in ('"', "'"):
            quote: str = c
            j: int = i + 1
            while j < n:
                if text_norm[j] == "`" and quote == '"':
                    j += 2
                    continue
                if text_norm[j] == quote:
                    if j + 1 < n and text_norm[j + 1] == quote:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            out.append(text_norm[i:j])
            i = j
            continue

        if c == "<" and i + 1 < n and text_norm[i + 1] == "#":
            close_at: int = text_norm.find("#>", i + 2)
            if close_at == -1:
                close_at = n
                block_end: int = n
            else:
                block_end = close_at + 2
            removed += 1
            line_start: int = text_norm.rfind("\n", 0, i) + 1
            before: str = text_norm[line_start:i]
            after_line_end: int = text_norm.find("\n", block_end)
            if after_line_end == -1:
                after_line_end = n
            after: str = text_norm[block_end:after_line_end]
            if before.strip() == "" and after.strip() == "":
                cut_n: int = i - line_start
                while out and cut_n > 0:
                    seg: str = out[-1]
                    if len(seg) <= cut_n:
                        cut_n -= len(seg)
                        out.pop()
                    else:
                        out[-1] = seg[:-cut_n]
                        cut_n = 0
                if after_line_end < n:
                    i = after_line_end + 1
                else:
                    i = after_line_end
                continue
            i = block_end
            continue

        if c == "#" and not (i + 1 < n and text_norm[i + 1] == "{"):
            line_end: int = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            line_start = text_norm.rfind("\n", 0, i) + 1
            before = text_norm[line_start:i]
            if i == 0 and text_norm.startswith("#!"):
                out.append(text_norm[i:line_end])
                i = line_end
                preserved += 1
                continue
            removed += 1
            if before.strip() == "":
                while out and out[-1].endswith(before) and before:
                    out[-1] = out[-1][: -len(before)]
                    break
                if line_end < n:
                    i = line_end + 1
                else:
                    i = line_end
                continue
            i = line_end
            continue

        out.append(c)
        i += 1

    new_text: str = "".join(out)
    new_text = _collapse_runs_only(new_text)
    if not new_text.endswith("\n"):
        new_text += "\n"
    return StripOutcome(
        new_text=_restore_line_endings(new_text, eol), removed=removed, preserved=preserved
    )


def strip_bat(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    lines: list[str] = text_norm.split("\n")
    out_lines: list[str] = []
    removed: int = 0
    for line in lines:
        body: str = line.lstrip()
        upper: str = body.upper()
        if upper.startswith("REM ") or upper == "REM" or body.startswith("::"):
            removed += 1
            continue
        out_lines.append(line)
    out_text: str = "\n".join(out_lines)
    out_text = _collapse_runs_only(out_text)
    if not out_text.endswith("\n"):
        out_text += "\n"
    return StripOutcome(new_text=_restore_line_endings(out_text, eol), removed=removed, preserved=0)


def strip_asm(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    lines: list[str] = text_norm.split("\n")
    out_lines: list[str] = []
    removed: int = 0
    preserved: int = 0

    for idx, line in enumerate(lines):
        if idx == 0 and line.startswith("#!"):
            out_lines.append(line)
            preserved += 1
            continue
        new_line: str = _strip_asm_inline(line)
        body: str = line.lstrip()
        if new_line == "" and (body.startswith(";") or body.startswith("#")):
            removed += 1
            continue
        if new_line != line:
            removed += 1
            if new_line.strip() == "":
                continue
            out_lines.append(new_line.rstrip())
        else:
            out_lines.append(line)

    out_text: str = "\n".join(out_lines)
    out_text = _collapse_runs_only(out_text)
    if not out_text.endswith("\n"):
        out_text += "\n"
    return StripOutcome(
        new_text=_restore_line_endings(out_text, eol), removed=removed, preserved=preserved
    )


def _strip_asm_inline(line: str) -> str:
    i: int = 0
    n: int = len(line)
    in_str: str | None = None
    while i < n:
        c: str = line[i]
        if in_str is not None:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == ";" or (c == "#" and i > 0):
            return line[:i].rstrip()
        i += 1
    return line


def strip_wat(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    out: list[str] = []
    i: int = 0
    n: int = len(text_norm)
    removed: int = 0

    while i < n:
        c: str = text_norm[i]
        if c == '"':
            j: int = i + 1
            while j < n:
                if text_norm[j] == "\\":
                    j += 2
                    continue
                if text_norm[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(text_norm[i:j])
            i = j
            continue
        if c == ";" and i + 1 < n and text_norm[i + 1] == ";":
            line_end: int = text_norm.find("\n", i)
            if line_end == -1:
                line_end = n
            removed += 1
            line_start: int = text_norm.rfind("\n", 0, i) + 1
            before: str = text_norm[line_start:i]
            if before.strip() == "":
                while out and out[-1].endswith(before) and before:
                    out[-1] = out[-1][: -len(before)]
                    break
                if line_end < n:
                    i = line_end + 1
                else:
                    i = line_end
                continue
            i = line_end
            continue
        if c == "(" and i + 1 < n and text_norm[i + 1] == ";":
            depth: int = 1
            j = i + 2
            while j < n and depth > 0:
                if j + 1 < n and text_norm[j] == "(" and text_norm[j + 1] == ";":
                    depth += 1
                    j += 2
                    continue
                if j + 1 < n and text_norm[j] == ";" and text_norm[j + 1] == ")":
                    depth -= 1
                    j += 2
                    continue
                j += 1
            removed += 1
            line_start = text_norm.rfind("\n", 0, i) + 1
            before = text_norm[line_start:i]
            after_line_end: int = text_norm.find("\n", j)
            if after_line_end == -1:
                after_line_end = n
            after: str = text_norm[j:after_line_end]
            if before.strip() == "" and after.strip() == "":
                cut_n: int = i - line_start
                while out and cut_n > 0:
                    seg: str = out[-1]
                    if len(seg) <= cut_n:
                        cut_n -= len(seg)
                        out.pop()
                    else:
                        out[-1] = seg[:-cut_n]
                        cut_n = 0
                if after_line_end < n:
                    i = after_line_end + 1
                else:
                    i = after_line_end
                continue
            i = j
            continue
        out.append(c)
        i += 1

    new_text: str = "".join(out)
    new_text = _collapse_runs_only(new_text)
    if not new_text.endswith("\n"):
        new_text += "\n"
    return StripOutcome(new_text=_restore_line_endings(new_text, eol), removed=removed, preserved=0)


def strip_erlang(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    lines: list[str] = text_norm.split("\n")
    out_lines: list[str] = []
    removed: int = 0
    preserved: int = 0

    for idx, line in enumerate(lines):
        if idx == 0 and line.startswith("#!"):
            out_lines.append(line)
            preserved += 1
            continue
        new_line: str = _strip_erlang_inline(line)
        body: str = line.lstrip()
        if new_line == "" and body.startswith("%"):
            removed += 1
            continue
        if new_line != line:
            removed += 1
            if new_line.strip() == "":
                continue
            out_lines.append(new_line.rstrip())
        else:
            out_lines.append(line)

    out_text: str = "\n".join(out_lines)
    out_text = _collapse_runs_only(out_text)
    if not out_text.endswith("\n"):
        out_text += "\n"
    return StripOutcome(
        new_text=_restore_line_endings(out_text, eol), removed=removed, preserved=preserved
    )


def _strip_erlang_inline(line: str) -> str:
    i: int = 0
    n: int = len(line)
    in_str: str | None = None
    while i < n:
        c: str = line[i]
        if in_str is not None:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == "%":
            return line[:i].rstrip()
        i += 1
    return line


def strip_elixir(text: str) -> StripOutcome:
    text_norm: str
    eol: str
    text_norm, eol = _normalize_line_endings(text)
    lines: list[str] = text_norm.split("\n")
    out_lines: list[str] = []
    removed: int = 0
    preserved: int = 0

    for idx, line in enumerate(lines):
        if idx == 0 and line.startswith("#!"):
            out_lines.append(line)
            preserved += 1
            continue
        new_line: str = _strip_elixir_inline(line)
        body: str = line.lstrip()
        if new_line == "" and body.startswith("#"):
            removed += 1
            continue
        if new_line != line:
            removed += 1
            if new_line.strip() == "":
                continue
            out_lines.append(new_line.rstrip())
        else:
            out_lines.append(line)

    out_text: str = "\n".join(out_lines)
    out_text = _collapse_runs_only(out_text)
    if not out_text.endswith("\n"):
        out_text += "\n"
    return StripOutcome(
        new_text=_restore_line_endings(out_text, eol), removed=removed, preserved=preserved
    )


def _strip_elixir_inline(line: str) -> str:
    i: int = 0
    n: int = len(line)
    in_str: str | None = None
    while i < n:
        c: str = line[i]
        if in_str is not None:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == "?" and i + 1 < n:
            i += 2
            continue
        if c == "#":
            if i + 1 < n and line[i + 1] == "{":
                i += 2
                continue
            return line[:i].rstrip()
        i += 1
    return line


EXCLUDED_NAME_SUBSTRINGS: tuple[str, ...] = (
    "obfuscated",
    "protected",
    "encrypted",
    ".obf.",
    ".min.",
    ".bundle.",
    ".encoded.",
    ".synth.",
    "synthesized",
    "_guarded",
    "_paced",
)

EXCLUDED_DIRS_REL: tuple[str, ...] = (
    "corpus/electron/",
    "corpus/mobile/apk/inbox/",
    "corpus/mobile/ipa/",
    "corpus/mobile/hermes/discord/",
    "corpus/mobile/flutter/",
    "corpus/mobile/nativescript/",
    "corpus/mobile/capacitor/",
    "corpus/mobile/xamarin/",
    "corpus/mobile/macho/",
    "corpus/mobile/macho-mac/",
    "corpus/python/obfuscators/",
    "corpus/src/pyarmor/",
    "corpus/src/nuitka/",
    "corpus/src/sourcedefender/",
    "corpus/src/pyinstaller/",
)

EXCLUDED_FILENAMES: tuple[str, ...] = (
    "generate.sh",
    "generate.ps1",
    "MANIFEST.toml",
)

EXT_HANDLERS: dict[str, tuple[str, Callable[[str], StripOutcome]]] = {
    ".py": ("python", strip_python),
    ".js": ("javascript", strip_js_ts),
    ".mjs": ("javascript", strip_js_ts),
    ".cjs": ("javascript", strip_js_ts),
    ".ts": ("typescript", strip_js_ts),
    ".tsx": ("typescript", strip_js_ts),
    ".jsx": ("javascript", strip_js_ts),
    ".lua": ("lua", strip_lua),
    ".rb": ("ruby", strip_ruby),
    ".php": ("php", strip_php),
    ".go": ("go", strip_go),
    ".rs": ("rust", strip_rust),
    ".java": ("java", strip_java_like),
    ".kt": ("kotlin", strip_kotlin_scala),
    ".scala": ("scala", strip_kotlin_scala),
    ".swift": ("swift", strip_swift),
    ".m": ("objc", strip_c_cpp),
    ".as": ("actionscript", strip_js_ts),
    ".c": ("c", strip_c_cpp),
    ".cpp": ("cpp", strip_c_cpp),
    ".cc": ("cpp", strip_c_cpp),
    ".cxx": ("cpp", strip_c_cpp),
    ".h": ("c-header", strip_c_cpp),
    ".hpp": ("cpp-header", strip_c_cpp),
    ".wat": ("wat", strip_wat),
    ".wast": ("wat", strip_wat),
    ".sh": ("shell", strip_shell),
    ".ps1": ("powershell", strip_powershell),
    ".bat": ("batch", strip_bat),
    ".cmd": ("batch", strip_bat),
    ".asm": ("asm", strip_asm),
    ".s": ("asm", strip_asm),
    ".S": ("asm", strip_asm),
    ".erl": ("erlang", strip_erlang),
    ".ex": ("elixir", strip_elixir),
    ".exs": ("elixir", strip_elixir),
}


EXCLUDED_PATH_SEGMENTS: tuple[str, ...] = (
    "/obfuscators/",
    "/protectors/",
    "/protected/",
)


def _is_excluded(rel_path: str, name: str) -> tuple[bool, str]:
    rel_unix: str = rel_path.replace(os.sep, "/")
    for ex_dir in EXCLUDED_DIRS_REL:
        if rel_unix.startswith(ex_dir) or ex_dir.rstrip("/") + "/" in rel_unix:
            return True, f"excluded-dir:{ex_dir}"
    for seg in EXCLUDED_PATH_SEGMENTS:
        if seg in "/" + rel_unix:
            return True, f"excluded-segment:{seg}"
    lower: str = name.lower()
    if lower.startswith("readme"):
        return True, "readme"
    if name in EXCLUDED_FILENAMES:
        return True, f"excluded-name:{name}"
    for sub in EXCLUDED_NAME_SUBSTRINGS:
        if sub in lower:
            return True, f"excluded-substring:{sub}"
    return False, ""


INCLUDED_TREES: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "corpus/src",
        frozenset(
            {
                ".py",
                ".js",
                ".mjs",
                ".cjs",
                ".ts",
                ".tsx",
                ".jsx",
                ".lua",
                ".rb",
                ".php",
                ".go",
                ".rs",
                ".java",
                ".kt",
                ".scala",
                ".swift",
                ".m",
                ".as",
                ".c",
                ".cpp",
                ".cc",
                ".cxx",
                ".h",
                ".hpp",
                ".wat",
                ".wast",
                ".sh",
                ".ps1",
                ".bat",
                ".cmd",
                ".asm",
                ".s",
                ".S",
            }
        ),
    ),
    ("corpus/python/decompile", frozenset({".py"})),
    ("corpus/python/obfuscators", frozenset({".py"})),
    ("corpus/javascript", frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})),
    ("corpus/jvm", frozenset({".java"})),
    ("corpus/lua", frozenset({".lua"})),
    ("corpus/ruby", frozenset({".rb"})),
    ("corpus/php", frozenset({".php"})),
    ("corpus/beam", frozenset({".erl", ".ex", ".exs"})),
)


def iter_target_files(project_root: Path) -> list[tuple[Path, str]]:
    results: list[tuple[Path, str]] = []
    for rel_root, allowed_exts in INCLUDED_TREES:
        tree_root: Path = project_root / rel_root
        if not tree_root.exists():
            continue
        for dirpath, _dirs, filenames in os.walk(tree_root):
            for fn in filenames:
                full: Path = Path(dirpath) / fn
                ext: str = full.suffix
                if ext not in allowed_exts:
                    continue
                if ext not in EXT_HANDLERS:
                    continue
                results.append((full, rel_root))
    return results


def main() -> int:
    project_root: Path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    corpus_root: Path = project_root / "corpus"
    if not corpus_root.exists():
        print(f"corpus root not found at {corpus_root}", file=sys.stderr)
        return 2

    stats: Stats = Stats()
    candidates: list[tuple[Path, str]] = iter_target_files(project_root)

    for path, _tree in candidates:
        rel_str: str = str(path.relative_to(project_root)).replace(os.sep, "/")
        excluded: bool
        reason: str
        excluded, reason = _is_excluded(rel_str, path.name)
        if excluded:
            stats.skipped.append((path, reason))
            continue

        ext: str = path.suffix
        lang: str
        handler: Callable[[str], StripOutcome]
        lang, handler = EXT_HANDLERS[ext]

        try:
            original_bytes: bytes = path.read_bytes()
        except OSError as e:
            stats.errors.append((path, f"read: {e!r}"))
            continue

        try:
            original: str = original_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                original = original_bytes.decode("latin-1")
            except UnicodeDecodeError as e:
                stats.errors.append((path, f"decode: {e!r}"))
                continue

        try:
            outcome: StripOutcome = handler(original)
        except Exception as e:
            stats.errors.append((path, f"strip:{lang}: {type(e).__name__}: {e}"))
            continue

        if outcome.new_text != original:
            try:
                path.write_text(outcome.new_text, encoding="utf-8", newline="")
            except OSError as e:
                stats.errors.append((path, f"write: {e!r}"))
                continue
            stats.bump_touched(lang)
            stats.add_removed(lang, outcome.removed)
            stats.add_preserved(lang, outcome.preserved)
        else:
            stats.add_preserved(lang, outcome.preserved)

    print("=== FILES TOUCHED (by language) ===")
    total_touched: int = 0
    for lang, n in sorted(stats.files_touched_by_lang.items(), key=lambda x: -x[1]):
        print(f"  {lang}: {n}")
        total_touched += n
    print(f"  TOTAL: {total_touched}")

    print("\n=== COMMENTS / DOCSTRINGS REMOVED (by language) ===")
    total_removed: int = 0
    for lang, n in sorted(stats.removed_by_lang.items(), key=lambda x: -x[1]):
        print(f"  {lang}: {n}")
        total_removed += n
    print(f"  TOTAL: {total_removed}")

    print("\n=== DIRECTIVES / SHEBANGS / ATTRS PRESERVED (by language) ===")
    total_preserved: int = 0
    for lang, n in sorted(stats.preserved_by_lang.items(), key=lambda x: -x[1]):
        print(f"  {lang}: {n}")
        total_preserved += n
    print(f"  TOTAL: {total_preserved}")

    print(f"\n=== SKIPPED ({len(stats.skipped)} files) ===")
    skip_reason_count: dict[str, int] = {}
    for _p, reason in stats.skipped:
        skip_reason_count[reason] = skip_reason_count.get(reason, 0) + 1
    for reason, n in sorted(skip_reason_count.items(), key=lambda x: -x[1]):
        print(f"  {reason}: {n}")

    if stats.errors:
        print(f"\n=== ERRORS ({len(stats.errors)}) ===")
        for p, msg in stats.errors[:50]:
            print(f"  {p.relative_to(project_root)}: {msg}")
        if len(stats.errors) > 50:
            print(f"  ... and {len(stats.errors) - 50} more")

    return 0 if not stats.errors else 1


if __name__ == "__main__":
    sys.exit(main())
