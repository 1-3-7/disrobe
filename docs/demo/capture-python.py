from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import sys
from datetime import datetime, timezone
from importlib.machinery import ModuleSpec
from pathlib import Path

import disrobe


def main() -> None:
    root: Path = Path(__file__).resolve().parents[2]
    input_path: Path = root / "playground/public/samples/add.wasm"
    data: bytes = input_path.read_bytes()
    lifted: disrobe.WasmLift = disrobe.wasm_lift(data, target="wat")
    if lifted.functions_emitted != 1 or not lifted.fully_recovered:
        raise RuntimeError("The add module must have one fully recovered function")
    if "i32.add" not in lifted.source:
        raise RuntimeError("Recovered WAT is missing the integer addition")
    spec: ModuleSpec | None = importlib.util.find_spec("disrobe.disrobe")
    if spec is None or spec.origin is None:
        raise RuntimeError("The native Python extension has no file identity")
    extension_path: Path = Path(spec.origin)
    with extension_path.open("rb") as extension:
        extension_hash: str = hashlib.file_digest(extension, "sha256").hexdigest()
    package_version: str = importlib.metadata.version("disrobe")
    if package_version != disrobe.__version__:
        raise RuntimeError("The package and native extension versions disagree")
    receipt: dict[str, object] = {
        "schema": "disrobe.demo.python/v1",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "package_version": package_version,
        "extension_sha256": extension_hash,
        "input": {
            "path": input_path.relative_to(root).as_posix(),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "result": {
            "target": lifted.target,
            "functions_emitted": lifted.functions_emitted,
            "fully_recovered": lifted.fully_recovered,
            "total_ops": lifted.total_ops,
            "translated_ops": lifted.translated_ops,
            "source": lifted.source,
        },
        "reproduction": "python docs/demo/capture-python.py",
    }
    destination: Path = root / "docs/demo/python.json"
    destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"Python {package_version}: recovered {lifted.functions_emitted} Wasm function")


if __name__ == "__main__":
    main()
