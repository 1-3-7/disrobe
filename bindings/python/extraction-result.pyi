from __future__ import annotations

from typing import Any, Literal, TypedDict, Union

class ExtractionResult(TypedDict, total=False):
    encoding: dict[str, str]
    entries: list[dict[str, Any]]
    integrity_violations: list[str]
    kind: str
    quota: dict[str, Any]

