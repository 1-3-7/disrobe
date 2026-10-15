"""Rebuild corpus/evm/vyper from corpus/evm/vyper-src with the Vyper compiler named by --vyper."""

import argparse
import hashlib
import json
import pathlib
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
MODES = ["gas", "codesize"]
SOURCES = ["Ledger.vy"]


def compile_one(vyper: str, source: pathlib.Path, mode: str) -> dict:
    formats = "bytecode,bytecode_runtime,abi,method_identifiers"
    out = subprocess.run(
        [vyper, "-O", mode, "-f", formats, source.name],
        cwd=source.parent,
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    ).stdout.strip().splitlines()
    creation, runtime, abi, identifiers = out[0], out[1], out[2], out[3]
    return {
        "creation": creation.removeprefix("0x"),
        "runtime": runtime.removeprefix("0x"),
        "abi": json.loads(abi),
        "identifiers": json.loads(identifiers),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vyper", required=True)
    args = parser.parse_args()
    version = subprocess.run(
        [args.vyper, "--version"], check=True, capture_output=True, text=True, timeout=120
    ).stdout.strip()
    for mode in MODES:
        out_dir = HERE / "vyper" / mode
        out_dir.mkdir(parents=True, exist_ok=True)
        reference = {"compiler": f"vyper {version}", "settings": {"optimize": mode}, "contracts": {}}
        for source in SOURCES:
            built = compile_one(args.vyper, HERE / "vyper-src" / source, mode)
            name = pathlib.Path(source).stem
            creation = bytes.fromhex(built["creation"])
            runtime = bytes.fromhex(built["runtime"])
            (out_dir / f"{name}.hex").write_text(built["creation"] + "\n", encoding="ascii", newline="\n")
            reference["contracts"][name] = {
                "source": source,
                "creation": {
                    "file": f"{name}.hex",
                    "length": len(creation),
                    "sha256": hashlib.sha256(creation).hexdigest(),
                },
                "runtime": {"length": len(runtime), "sha256": hashlib.sha256(runtime).hexdigest()},
                "methodIdentifiers": {
                    signature: f"{int(value, 16):08x}" for signature, value in sorted(built["identifiers"].items())
                },
                "constantGetters": [],
                "requireMessages": [],
                "abi": built["abi"],
            }
        (out_dir / "reference.json").write_text(json.dumps(reference, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"{version} -O {mode}: {len(SOURCES)} contracts -> {out_dir}")


if __name__ == "__main__":
    main()
