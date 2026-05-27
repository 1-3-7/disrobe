from __future__ import annotations

from typing import Any, Literal, TypedDict, Union

class FreezerManifest(TypedDict, total=False):
    entries: list[dict[str, Any]]
    entry_count: int
    interpreter_hint: None | str
    kind: Literal["cx-freeze", "py2exe", "shiv", "pex", "py-oxidizer", "briefcase", "unknown"]
    primary_module: None | str
    python_major: None | int
    python_minor: None | int
    schema: Literal["disrobe.pyfreeze.manifest/v0"]
    source_path: str

