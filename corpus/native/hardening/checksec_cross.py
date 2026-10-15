import sys
import tomllib
from importlib.metadata import version
from pathlib import Path

from pwnlib.elf.elf import ELF

HERE = Path(__file__).resolve().parent

DIVERGENCES = {
    ("elf-x86_64-dso.so", "stack-canary"): "pwntools counts the stub's own definition of __stack_chk_fail; disrobe counts imports of a dynamically linked image",
}


def pwntools_verdicts(elf):
    relro = {"Full": "present", "Partial": "partial", None: "absent"}[elf.relro]
    verdicts = {
        "nx": "present" if elf.nx else "absent",
        "relro": relro,
        "stack-canary": "present" if elf.canary else "absent",
        "rpath": "present" if elf.rpath else "absent",
        "runpath": "present" if elf.runpath else "absent",
        "symbols": "present" if elf.get_section_by_name(".symtab") is not None else "absent",
        "pie": "present" if elf.pie else "absent",
        "fortify": "present" if elf.fortify else "absent",
    }
    if elf.arch in ("amd64", "i386"):
        verdicts["ibt"] = "present" if elf.ibt else "absent"
        verdicts["shstk"] = "present" if elf.shadowstack else "absent"
    return verdicts


def main():
    manifest = tomllib.loads((HERE / "MANIFEST.toml").read_text(encoding="utf-8"))
    compared = 0
    disagreements = []
    for fixture in manifest["fixture"]:
        if fixture["format"] != "elf":
            continue
        elf = ELF(str(HERE / fixture["path"]), checksec=False)
        observed = pwntools_verdicts(elf)
        for prop, expected in sorted(fixture["expect"].items()):
            if prop not in observed or expected not in ("present", "partial", "absent"):
                continue
            if (fixture["name"], prop) in DIVERGENCES:
                continue
            compared += 1
            if observed[prop] != expected:
                disagreements.append(f"{fixture['name']}: {prop} manifest {expected}, pwntools {observed[prop]}")
    print(f"pwntools {version('pwntools')} checksec agrees on {compared - len(disagreements)}/{compared} ELF verdicts")
    for line in disagreements:
        print(line)
    for (name, prop), reason in sorted(DIVERGENCES.items()):
        print(f"known divergence {name} {prop}: {reason}")
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
