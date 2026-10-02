import hashlib
import json
import os
import pathlib
import sys


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    repo = pathlib.Path(os.environ["REPO"])
    out = pathlib.Path(os.environ["OUT"])
    tool: dict[str, str] = {}
    for line in (out / "tool.env").read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        tool[key] = value
    outputs = []
    for row in (out / "outputs.tsv").read_text(encoding="utf-8").splitlines():
        output, source, command, behaviour = row.split("\t")
        entry: dict[str, str | int] = {
            "input": source,
            "input_sha256": sha256(repo / source),
            "command": command,
            "behaviour": behaviour,
        }
        if output != "-":
            entry["output"] = output
            entry["output_sha256"] = sha256(out / output)
            entry["output_bytes"] = (out / output).stat().st_size
        outputs.append(entry)
    record = {
        "tool": tool,
        "recipe": os.environ["RECIPE"],
        "repository_commit": os.environ["GITHUB_SHA"],
        "workflow_run": f'{os.environ["GITHUB_SERVER_URL"]}/{os.environ["GITHUB_REPOSITORY"]}/actions/runs/{os.environ["GITHUB_RUN_ID"]}',
        "runner_image": f'{os.environ.get("ImageOS", "")} {os.environ.get("ImageVersion", "")}'.strip(),
        "outputs": outputs,
    }
    (out / "build-record.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    failed = [entry for entry in outputs if entry["behaviour"] != "same"]
    for entry in failed:
        print(f'{entry["input"]}: {entry["command"]}: {entry["behaviour"]}', file=sys.stderr)
    print(f"{len(outputs) - len(failed)} of {len(outputs)} outputs behave like their input")
    return 0 if len(failed) < len(outputs) else 1


if __name__ == "__main__":
    sys.exit(main())
