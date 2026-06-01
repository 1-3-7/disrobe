from __future__ import annotations

from string.templatelib import Interpolation, Template

__PY_BAND__: tuple[int, int] = (3, 14)


def tstring_basic(name: str, count: int) -> Template:
    return t"hello {name}, count={count}"


def tstring_with_conversion(value: object) -> Template:
    return t"raw={value!r}, str={value!s}, ascii={value!a}"


def tstring_with_format_spec(x: float, width: int) -> Template:
    return t"value={x:{width}.2f}"


def tstring_concatenation(prefix: str, items: list[int]) -> Template:
    return t"{prefix}: [{', '.join(str(i) for i in items)}] / total={sum(items)}"


def render_template(template: Template) -> str:
    out: list[str] = []
    for part in template:
        if isinstance(part, str):
            out.append(part)
        elif isinstance(part, Interpolation):
            out.append(format(part.value, part.format_spec or ""))
    return "".join(out)


def safe_html_demo(user_input: str, role: str) -> str:
    template: Template = t"<div role={role}>{user_input}</div>"
    pieces: list[str] = []
    for part in template:
        if isinstance(part, str):
            pieces.append(part)
        elif isinstance(part, Interpolation):
            raw = str(part.value)
            pieces.append(raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    return "".join(pieces)
