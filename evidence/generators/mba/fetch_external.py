from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from pathlib import Path
from typing import Final

UPSTREAM_URL: Final[str] = "https://github.com/nhpcc502/MBA-Obfuscator.git"
UPSTREAM_COMMIT: Final[str] = "8574ef8537f884ed7bd38da7b7bc630e8e8fc8f6"
CACHE_RELATIVE: Final[str] = "target/mba-external/MBA-Obfuscator"
OUTPUT_RELATIVE: Final[str] = "evidence/corpus/mba/external/mba-obfuscator.jsonl"

KERNELS: Final[tuple[str, ...]] = (
    "x+y",
    "x-y",
    "x^y",
    "x&y",
    "x|y",
    "~x",
    "-x",
    "2*x+3*y",
    "x&~y",
    "~(x|y)",
    "x+y+z",
    "(x&y)+(x|y)",
)

MODES: Final[tuple[str, ...]] = ("l", "p", "np_zero", "np_recur", "np_replace")

PER_CASE_TIMEOUT_SECONDS: Final[float] = 90.0


def repository_root(start: Path, /) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "Cargo.toml").is_file() and (candidate / "crates").is_dir():
            return candidate
    raise SystemExit(f"no repository root above {start}")


def ensure_upstream(cache: Path, /) -> Path:
    if not (cache / ".git").is_dir():
        cache.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--quiet", UPSTREAM_URL, str(cache)],
            check=True,
        )
    subprocess.run(
        ["git", "-C", str(cache), "fetch", "--quiet", "origin", UPSTREAM_COMMIT],
        check=False,
    )
    subprocess.run(
        ["git", "-C", str(cache), "checkout", "--quiet", UPSTREAM_COMMIT],
        check=True,
    )
    resolved: str = subprocess.run(
        ["git", "-C", str(cache), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if resolved != UPSTREAM_COMMIT:
        raise SystemExit(f"upstream checkout is {resolved}, expected {UPSTREAM_COMMIT}")
    return cache


def run_one(cache: Path, kernel: str, mode: str, seed: int, /) -> str | None:
    completed: subprocess.CompletedProcess[str] = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--single",
            "--cache",
            str(cache),
            "--kernel",
            kernel,
            "--mode",
            mode,
            "--seed",
            str(seed),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=PER_CASE_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        print(f"skip {kernel} {mode}: {completed.stderr.strip()[:200]}", file=sys.stderr)
        return None
    produced: str = completed.stdout.strip()
    return produced or None


def single(cache: Path, kernel: str, mode: str, seed: int, /) -> int:
    import importlib.util
    import os
    import types

    import numpy

    for name, builtin in (
        ("int", int),
        ("long", int),
        ("float", float),
        ("bool", bool),
    ):
        if not hasattr(numpy, name):
            setattr(numpy, name, builtin)

    package: Path = cache / "mba_obfuscator"
    sys.path.insert(0, str(package))
    sys.path.insert(0, str(package / "tools"))
    sys.path.insert(0, str(package / "mba_obfuscator"))
    os.chdir(package / "mba_obfuscator")

    spec = importlib.util.spec_from_file_location(
        "upstream_entry", package / "mba_obfuscator" / "mba_obfuscator.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the upstream entry point")
    engine: types.ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)

    random.seed(seed)
    produced: object = engine.mba_obfuscator(kernel, mode)
    if not isinstance(produced, str) or not produced.strip():
        raise SystemExit("upstream produced no expression")
    sys.stdout.write(produced.strip())
    return 0


def main() -> int:
    parser: argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("--single", action="store_true")
    parser.add_argument("--cache", type=Path, default=None)
    parser.add_argument("--kernel", type=str, default="")
    parser.add_argument("--mode", type=str, default="")
    parser.add_argument("--seed", type=int, default=0)
    arguments: argparse.Namespace = parser.parse_args()

    if arguments.single:
        if arguments.cache is None:
            raise SystemExit("--single needs --cache")
        return single(arguments.cache, arguments.kernel, arguments.mode, arguments.seed)

    root: Path = repository_root(Path(__file__).resolve().parent)
    cache: Path = ensure_upstream(root / CACHE_RELATIVE)
    rows: list[dict[str, object]] = []
    for kernel_index, kernel in enumerate(KERNELS):
        for mode_index, mode in enumerate(MODES):
            seed: int = 0x5EED0000 + kernel_index * 97 + mode_index
            try:
                produced: str | None = run_one(cache, kernel, mode, seed)
            except subprocess.TimeoutExpired:
                print(f"skip {kernel} {mode}: exceeded the time budget", file=sys.stderr)
                continue
            if produced is None:
                continue
            rows.append(
                {
                    "kernel": kernel,
                    "mode": mode,
                    "obfuscated": produced,
                    "seed": seed,
                }
            )
            print(f"kept {kernel} {mode} ({len(produced)} characters)", file=sys.stderr)

    rows.sort(key=lambda row: (str(row["mode"]), int(str(row["seed"]))))
    target: Path = root / OUTPUT_RELATIVE
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"wrote {len(rows)} rows to {target}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
