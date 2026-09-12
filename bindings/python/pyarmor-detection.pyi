from __future__ import annotations

from typing import Any, Literal, TypedDict, Union

class PyarmorDetection(TypedDict, total=False):
    confidence: Literal["low", "medium", "high"]
    diagnostics: list[str]
    protection: Literal["standard", "super-mode", "bcc", "no-wrap"]
    serial: None | str
    version: Literal["v3", "v4", "v5", "v6", "v7", "v8", "v9"]

