#!/usr/bin/env python3
"""Generate a GitHub wiki tree from the mdBook source under docs/src.

docs/src is the single source of truth. This transform reads the mdBook
sources and emits a wiki tree (Home.md, _Sidebar.md, _Footer.md, and one
page per docs/src/**/*.md) into an output directory. The wiki is never
edited by hand; CI runs this script and pushes the result.

Run `python scripts/wiki_sync.py --out wiki` to generate, or
`python scripts/wiki_sync.py --check --out wiki` to fail on drift.
"""

from __future__ import annotations

import argparse
import filecmp
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
DOCS_SRC: Path = REPO_ROOT / "docs" / "src"
SUMMARY_NAME: str = "SUMMARY.md"
INTRODUCTION_NAME: str = "introduction.md"
HOME_PAGE: str = "Home"
RAW_ASSET_BASE: str = "https://raw.githubusercontent.com/1-3-7/disrobe/main"

LINK_RE: re.Pattern[str] = re.compile(r"(?<!\!)\[([^\]]*)\]\(([^)]+)\)")
IMAGE_RE: re.Pattern[str] = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
SUMMARY_ITEM_RE: re.Pattern[str] = re.compile(
    r"^(?P<indent>\s*)[-*]\s+\[(?P<title>[^\]]*)\]\((?P<target>[^)]+)\)\s*$"
)
SUMMARY_PREFIX_RE: re.Pattern[str] = re.compile(
    r"^\[(?P<title>[^\]]*)\]\((?P<target>[^)]+)\)\s*$"
)
SUMMARY_PART_RE: re.Pattern[str] = re.compile(r"^#\s+(?P<title>.+?)\s*$")
HEADING_RE: re.Pattern[str] = re.compile(r"^#\s+(?P<title>.+?)\s*$")
INCLUDE_LINE_RE: re.Pattern[str] = re.compile(r"^\s*\{\{#[^}]*\}\}\s*$")
INCLUDE_INLINE_RE: re.Pattern[str] = re.compile(r"\{\{#[^}]*\}\}")
TOC_DIRECTIVE_RE: re.Pattern[str] = re.compile(
    r"^\s*<!--\s*(?:toc|/?toc|mdbook-[^>]*)\s*-->\s*$", re.IGNORECASE
)
HIDDEN_RUST_LINE_RE: re.Pattern[str] = re.compile(r"^#(\s.*)?$|^#$")
EXTERNAL_TARGET_RE: re.Pattern[str] = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//|#)")
RUST_FENCE_LANGS: frozenset[str] = frozenset(
    {"rust", "rs", "rust,no_run", "rust,ignore", "rust,should_panic", "rust,edition2021"}
)


@dataclass(frozen=True)
class Page:
    source: Path
    rel_posix: str
    wiki_name: str
    wiki_rel: str


def discover_pages() -> list[Page]:
    pages: list[Page] = []
    for source in sorted(DOCS_SRC.rglob("*.md")):
        rel: Path = source.relative_to(DOCS_SRC)
        rel_posix: str = rel.as_posix()
        if rel_posix == SUMMARY_NAME:
            continue
        if rel_posix == INTRODUCTION_NAME:
            pages.append(Page(source, rel_posix, HOME_PAGE, f"{HOME_PAGE}.md"))
            continue
        wiki_name: str = rel.with_suffix("").as_posix()
        pages.append(Page(source, rel_posix, wiki_name, f"{wiki_name}.md"))
    return pages


def wiki_name_for_rel(rel_posix: str) -> str:
    if rel_posix == INTRODUCTION_NAME:
        return HOME_PAGE
    if rel_posix.endswith(".md"):
        return rel_posix[: -len(".md")]
    return rel_posix


def resolve_doc_target(source: Path, target: str) -> str | None:
    raw: str = target.strip()
    if not raw or EXTERNAL_TARGET_RE.match(raw):
        return None
    anchor: str = ""
    if "#" in raw:
        raw, anchor = raw.split("#", 1)
        anchor = "#" + anchor
    if not raw:
        return None
    if not raw.endswith(".md"):
        return None
    resolved: Path = (source.parent / raw).resolve()
    try:
        rel: Path = resolved.relative_to(DOCS_SRC)
    except ValueError:
        return None
    return wiki_name_for_rel(rel.as_posix()) + anchor


def resolve_asset_url(source: Path, target: str) -> str | None:
    raw: str = target.strip()
    if not raw or EXTERNAL_TARGET_RE.match(raw):
        return None
    path_part: str = raw.split("#", 1)[0].split("?", 1)[0]
    if not path_part:
        return None
    resolved: Path = (source.parent / path_part).resolve()
    try:
        rel: Path = resolved.relative_to(REPO_ROOT)
    except ValueError:
        return None
    if not resolved.exists():
        return None
    return f"{RAW_ASSET_BASE}/{rel.as_posix()}"


def rewrite_images(source: Path, text: str, warnings: list[str]) -> str:
    def repl(match: re.Match[str]) -> str:
        alt: str = match.group(1)
        target: str = match.group(2)
        url: str | None = resolve_asset_url(source, target)
        if url is None:
            if not EXTERNAL_TARGET_RE.match(target.strip()):
                warnings.append(
                    f"{source.relative_to(REPO_ROOT).as_posix()}: image {target!r} did not resolve to a repo asset"
                )
            return match.group(0)
        return f"![{alt}]({url})"

    return IMAGE_RE.sub(repl, text)


def rewrite_links(source: Path, text: str, warnings: list[str]) -> str:
    def repl(match: re.Match[str]) -> str:
        label: str = match.group(1)
        target: str = match.group(2)
        rewritten: str | None = resolve_doc_target(source, target)
        if rewritten is None:
            if target.strip().endswith(".md") and not EXTERNAL_TARGET_RE.match(
                target.strip()
            ):
                warnings.append(
                    f"{source.relative_to(REPO_ROOT).as_posix()}: link {target!r} did not resolve to a docs page"
                )
            return match.group(0)
        return f"[{label}]({rewritten})"

    return LINK_RE.sub(repl, text)


def strip_mdbook_isms(text: str) -> str:
    lines: list[str] = text.splitlines()
    out: list[str] = []
    in_fence: bool = False
    fence_marker: str = ""
    fence_is_rust: bool = False
    for line in lines:
        stripped: str = line.strip()
        fence_open: re.Match[str] | None = re.match(r"^(```+|~~~+)(.*)$", stripped)
        if fence_open and not in_fence:
            in_fence = True
            fence_marker = fence_open.group(1)[0] * len(fence_open.group(1))
            info: str = fence_open.group(2).strip().lower()
            fence_is_rust = info in RUST_FENCE_LANGS or info.startswith("rust")
            out.append(line)
            continue
        if in_fence:
            if stripped.startswith(fence_marker) and stripped.strip(fence_marker[0]) == "":
                in_fence = False
                fence_is_rust = False
                out.append(line)
                continue
            if fence_is_rust and HIDDEN_RUST_LINE_RE.match(line) and not stripped.startswith("##"):
                continue
            if INCLUDE_LINE_RE.match(line):
                continue
            out.append(INCLUDE_INLINE_RE.sub("", line))
            continue
        if INCLUDE_LINE_RE.match(line):
            continue
        if TOC_DIRECTIVE_RE.match(line):
            continue
        out.append(INCLUDE_INLINE_RE.sub("", line))
    result: str = "\n".join(out)
    if text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def page_title(source: Path, text: str) -> str:
    for line in text.splitlines():
        heading: re.Match[str] | None = HEADING_RE.match(line)
        if heading:
            return heading.group("title").strip()
    return source.stem.replace("-", " ")


def transform_page(page: Page, warnings: list[str]) -> str:
    text: str = page.source.read_text(encoding="utf-8")
    text = strip_mdbook_isms(text)
    text = rewrite_images(page.source, text, warnings)
    text = rewrite_links(page.source, text, warnings)
    if not text.endswith("\n"):
        text += "\n"
    return text


def build_sidebar(pages_by_rel: dict[str, Page], warnings: list[str]) -> str:
    summary_path: Path = DOCS_SRC / SUMMARY_NAME
    if not summary_path.exists():
        warnings.append("docs/src/SUMMARY.md is missing; sidebar will be empty")
        return f"### [{HOME_PAGE}]({HOME_PAGE})\n"
    lines: list[str] = summary_path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    for line in lines:
        part: re.Match[str] | None = SUMMARY_PART_RE.match(line)
        if part and not line.startswith("# Summary"):
            out.append("")
            out.append(f"**{part.group('title').strip()}**")
            continue
        prefix: re.Match[str] | None = SUMMARY_PREFIX_RE.match(line.strip())
        if prefix:
            link: str | None = summary_link(summary_path, prefix.group("target"))
            if link is not None:
                out.append(f"- [{prefix.group('title').strip()}]({link})")
            continue
        item: re.Match[str] | None = SUMMARY_ITEM_RE.match(line)
        if item:
            depth: int = len(item.group("indent").replace("\t", "  ")) // 2
            link2: str | None = summary_link(summary_path, item.group("target"))
            if link2 is not None:
                out.append(f"{'  ' * depth}- [{item.group('title').strip()}]({link2})")
            continue
    body: str = "\n".join(part for part in out).strip("\n")
    return body + "\n"


def summary_link(summary_path: Path, target: str) -> str | None:
    resolved: str | None = resolve_doc_target(summary_path, target)
    if resolved is None:
        return None
    return resolved


def footer_text() -> str:
    return (
        "This wiki is generated from `docs/src` in the "
        "[disrobe repository](https://github.com/1-3-7/disrobe) by "
        "`scripts/wiki_sync.py`. Edit the docs there, not the wiki pages here.\n"
    )


def write_output(out_dir: Path, warnings: list[str]) -> int:
    pages: list[Page] = discover_pages()
    pages_by_rel: dict[str, Page] = {page.rel_posix: page for page in pages}
    rendered: dict[str, str] = {}
    for page in pages:
        rendered[page.wiki_rel] = transform_page(page, warnings)
    rendered["_Sidebar.md"] = build_sidebar(pages_by_rel, warnings)
    rendered["_Footer.md"] = footer_text()

    managed: set[Path] = set()
    for rel, content in sorted(rendered.items()):
        dest: Path = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8", newline="\n")
        managed.add(dest.resolve())
    prune_stale(out_dir, managed)
    return len(rendered)


def prune_stale(out_dir: Path, managed: set[Path]) -> None:
    for existing in sorted(out_dir.rglob("*.md")):
        if ".git" in existing.parts:
            continue
        if existing.resolve() not in managed:
            existing.unlink()
    for directory in sorted(out_dir.rglob("*"), reverse=True):
        if not directory.is_dir() or ".git" in directory.parts:
            continue
        if not any(directory.iterdir()):
            directory.rmdir()


def diff_trees(generated: Path, existing: Path) -> list[str]:
    drift: list[str] = []
    gen_files: dict[str, Path] = {
        path.relative_to(generated).as_posix(): path
        for path in generated.rglob("*.md")
        if ".git" not in path.parts
    }
    cur_files: dict[str, Path] = {
        path.relative_to(existing).as_posix(): path
        for path in existing.rglob("*.md")
        if ".git" not in path.parts
    }
    for rel in sorted(set(gen_files) | set(cur_files)):
        if rel not in cur_files:
            drift.append(f"missing in output: {rel}")
        elif rel not in gen_files:
            drift.append(f"stale in output: {rel}")
        elif not filecmp.cmp(gen_files[rel], cur_files[rel], shallow=False):
            drift.append(f"content differs: {rel}")
    return drift


def run_check(out_dir: Path) -> int:
    warnings: list[str] = []
    with tempfile.TemporaryDirectory(prefix="wiki-sync-") as tmp:
        tmp_dir: Path = Path(tmp)
        write_output(tmp_dir, warnings)
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        if not out_dir.exists():
            print(f"check failed: output dir {out_dir} does not exist", file=sys.stderr)
            return 1
        drift: list[str] = diff_trees(tmp_dir, out_dir)
    if drift:
        print("wiki output is stale; run scripts/wiki_sync.py to regenerate:", file=sys.stderr)
        for entry in drift:
            print(f"  {entry}", file=sys.stderr)
        return 1
    print(f"wiki output in {out_dir} is up to date")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="wiki_sync",
        description="Generate the GitHub wiki tree from docs/src (single source of truth).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(".wiki-build"),
        help="output directory for the generated wiki tree (default: ./.wiki-build)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate into a temp dir and exit nonzero if --out has drifted",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args: argparse.Namespace = parse_args(argv)
    out_dir: Path = args.out.resolve()
    if not DOCS_SRC.is_dir():
        print(f"error: docs source not found at {DOCS_SRC}", file=sys.stderr)
        return 2
    if args.check:
        return run_check(out_dir)
    warnings: list[str] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    count: int = write_output(out_dir, warnings)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"wrote {count} wiki files to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
