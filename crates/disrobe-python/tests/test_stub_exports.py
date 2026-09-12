from __future__ import annotations

import ast
import inspect
from pathlib import Path

import disrobe


def test_public_runtime_exports_have_stub_declarations() -> None:
    root: Path = Path(__file__).resolve().parents[3]
    stub: ast.Module = ast.parse(
        (root / "bindings/python/disrobe/__init__.pyi").read_text(encoding="utf-8")
    )
    declared_functions: set[str] = {
        node.name for node in stub.body if isinstance(node, ast.FunctionDef)
    }
    declared_classes: set[str] = {
        node.name for node in stub.body if isinstance(node, ast.ClassDef)
    }
    runtime_functions: set[str] = set()
    runtime_classes: set[str] = set()
    for name in dir(disrobe):
        if name.startswith("_"):
            continue
        value: object = getattr(disrobe, name)
        if inspect.isbuiltin(value):
            runtime_functions.add(name)
        elif inspect.isclass(value):
            runtime_classes.add(name)

    assert runtime_functions == declared_functions
    assert runtime_classes <= declared_classes
