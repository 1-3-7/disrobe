from __future__ import annotations

import hashlib
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Final

CACHE_RELATIVE: Final[str] = "target/mba-datasets"


@dataclass(frozen=True, slots=True)
class PinnedFile:
    local_name: str
    url: str
    sha256: str
    licence: str


PINNED: Final[tuple[PinnedFile, ...]] = (
    PinnedFile(
        local_name="mba-blast-dataset1.txt",
        url=(
            "https://raw.githubusercontent.com/softsec-unh/MBA-Blast/"
            "ceb12c28ac25ada0b5b9f3ffbf4dcec8e8fa3c39/dataset/dataset1.txt"
        ),
        sha256="f7e03e345f6464ca5e7f9cb0077761cddb9b463d0841b68be3ded2f8ca89120c",
        licence="no licence file upstream, so the bytes are fetched and never redistributed",
    ),
    PinnedFile(
        local_name="mba-solver-linear.txt",
        url=(
            "https://raw.githubusercontent.com/softsec-unh/MBA-Solver/"
            "c76231aadb8b033d9e8e6be2baa05ff1464f247e/dataset/pldi_dataset_linear_MBA.txt"
        ),
        sha256="393f1d38eefc8c8a2a20a903e5365029709de67bda03915108df5caf0a4018bf",
        licence="GPL-3.0 upstream, so the bytes are fetched and never redistributed",
    ),
    PinnedFile(
        local_name="mba-solver-poly.txt",
        url=(
            "https://raw.githubusercontent.com/softsec-unh/MBA-Solver/"
            "c76231aadb8b033d9e8e6be2baa05ff1464f247e/dataset/pldi_dataset_poly_MBA.txt"
        ),
        sha256="44742af8dc522f5200cf2b73976cbcea064b8d362707ee22671127358f345e5f",
        licence="GPL-3.0 upstream, so the bytes are fetched and never redistributed",
    ),
    PinnedFile(
        local_name="mba-solver-nonpoly.txt",
        url=(
            "https://raw.githubusercontent.com/softsec-unh/MBA-Solver/"
            "c76231aadb8b033d9e8e6be2baa05ff1464f247e/dataset/pldi_dataset_nonpoly_MBA.txt"
        ),
        sha256="752271469a742963b412f0ee851f8d126277d6430cc761fd45c76a9c9bf087b3",
        licence="GPL-3.0 upstream, so the bytes are fetched and never redistributed",
    ),
    PinnedFile(
        local_name="loki-add-depth1.txt",
        url=(
            "https://raw.githubusercontent.com/RUB-SysSec/loki/"
            "a3b5717d9cd7a8f8b6cbf92399de59554c4cc55c/"
            "experiments/experiment_10_mba_formula/data/add_depth1.txt"
        ),
        sha256="f346a23d7f05203fee4b7043a2c3d4e5c269c1690bd6f4f64a728c7bef6e691d",
        licence="AGPL-3.0 upstream, so the bytes are fetched and never redistributed",
    ),
    PinnedFile(
        local_name="loki-add-depth2.txt",
        url=(
            "https://raw.githubusercontent.com/RUB-SysSec/loki/"
            "a3b5717d9cd7a8f8b6cbf92399de59554c4cc55c/"
            "experiments/experiment_10_mba_formula/data/add_depth2.txt"
        ),
        sha256="22377511aafce2a73a473ebe608fb2bf55f38ec313621e7d6c64506302ce2185",
        licence="AGPL-3.0 upstream, so the bytes are fetched and never redistributed",
    ),
)


def repository_root(start: Path, /) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "Cargo.toml").is_file() and (candidate / "crates").is_dir():
            return candidate
    raise SystemExit(f"no repository root above {start}")


def digest(payload: bytes, /) -> str:
    return hashlib.sha256(payload).hexdigest()


def fetch(pinned: PinnedFile, target: Path, /) -> bool:
    if target.is_file() and digest(target.read_bytes()) == pinned.sha256:
        print(f"cached {pinned.local_name}", file=sys.stderr)
        return True
    request: urllib.request.Request = urllib.request.Request(
        pinned.url, headers={"User-Agent": "disrobe-evidence-corpus"}
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload: bytes = response.read()
    produced: str = digest(payload)
    if produced != pinned.sha256:
        print(
            f"REFUSED {pinned.local_name}: sha256 {produced} does not match the pin {pinned.sha256}",
            file=sys.stderr,
        )
        return False
    target.write_bytes(payload)
    print(f"fetched {pinned.local_name} ({len(payload)} bytes)", file=sys.stderr)
    return True


def main() -> int:
    root: Path = repository_root(Path(__file__).resolve().parent)
    cache: Path = root / CACHE_RELATIVE
    cache.mkdir(parents=True, exist_ok=True)
    failures: int = 0
    for pinned in PINNED:
        if not fetch(pinned, cache / pinned.local_name):
            failures += 1
    print(f"dataset cache at {cache}, {len(PINNED) - failures} of {len(PINNED)} pinned files ready")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
