#!/usr/bin/env bash
set -euo pipefail

bin="${DISROBE_BIN:-disrobe}"
python="${DISROBE_PYTHON:-python3}"
block_passes="${DISROBE_BLOCK_PASSES:-native.packer-unpack,pyarmor.unpack,pyinstaller.extract,sourcedefender.decrypt,nuitka.extract,pyfreeze.extract}"
block_families="${DISROBE_BLOCK_FAMILIES:-}"

if ! command -v "${bin}" >/dev/null 2>&1; then
  echo "disrobe-gate: '${bin}' not found on PATH." >&2
  echo "disrobe-gate: install from https://github.com/1-3-7/disrobe/releases or set DISROBE_BIN." >&2
  exit 1
fi

if ! command -v "${python}" >/dev/null 2>&1; then
  echo "disrobe-gate: '${python}' is required to parse the chain report; set DISROBE_PYTHON to a Python 3 executable." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  exit 0
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/disrobe-gate.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

status=0
detected=0
analysis_failed=0
for file in "$@"; do
  [ -f "${file}" ] || continue

  outdir="${workdir}/out"
  report="${workdir}/report.json"
  analyzer_error="${workdir}/analyzer-error.txt"
  analyzer_status=0
  "${bin}" auto "${file}" --json --out "${outdir}" >"${report}" 2>"${analyzer_error}" || analyzer_status=$?
  rm -rf "${outdir}"
  if [ "${analyzer_status}" -ne 0 ]; then
    echo "disrobe-gate: analyzer exited ${analyzer_status} while scanning '${file}'." >&2
    if [ -s "${analyzer_error}" ]; then
      echo "disrobe-gate: $(head -n 1 "${analyzer_error}")" >&2
    fi
    status=1
    analysis_failed=1
    continue
  fi
  if [ ! -s "${report}" ]; then
    echo "disrobe-gate: analyzer produced no JSON report for '${file}'." >&2
    status=1
    analysis_failed=1
    continue
  fi

  parser_error="${workdir}/parser-error.txt"
  if ! hit="$(DR_PASSES="${block_passes}" DR_FAMILIES="${block_families}" "${python}" -c '
import json, os, sys
def fail(message):
    print(message, file=sys.stderr)
    sys.exit(2)
passes = {p.strip() for p in os.environ.get("DR_PASSES", "").split(",") if p.strip()}
families = {f.strip() for f in os.environ.get("DR_FAMILIES", "").split(",") if f.strip()}
try:
    doc = json.load(sys.stdin)
except ValueError as error:
    fail(str(error))
if not isinstance(doc, dict):
    fail("report root must be an object")
if "nodes" not in doc:
    fail("report must contain nodes")
nodes = doc["nodes"]
if not isinstance(nodes, list):
    fail("report nodes must be an array")
hits = []
for node in nodes:
    if not isinstance(node, dict):
        fail("each report node must be an object")
    if "detector_picks" not in node:
        fail("report node must contain detector_picks")
    picks = node["detector_picks"]
    if not isinstance(picks, list):
        fail("detector_picks must be an array")
    for pick in picks:
        if not isinstance(pick, dict):
            fail("each detector pick must be an object")
        for field, field_type, type_name in (
            ("chosen", bool, "a boolean"),
            ("pass_id", str, "a string"),
            ("family", str, "a string"),
        ):
            if field not in pick:
                fail("detector pick must contain {}".format(field))
            if type(pick[field]) is not field_type:
                fail("detector pick {} must be {}".format(field, type_name))
        if not pick["chosen"]:
            continue
        pid = pick["pass_id"]
        fam = pick["family"]
        if pid in passes or (fam in families):
            hits.append("{} ({})".format(pid, fam))
if hits:
    print("; ".join(sorted(set(hits))))
' <"${report}" 2>"${parser_error}")"; then
    echo "disrobe-gate: invalid JSON report for '${file}': $(head -n 1 "${parser_error}")" >&2
    status=1
    analysis_failed=1
    continue
  fi

  if [ -n "${hit}" ]; then
    echo "disrobe-gate: BLOCKED ${file}: ${hit}" >&2
    status=1
    detected=1
  fi
done

if [ "${detected}" -ne 0 ]; then
  echo "disrobe-gate: commit blocked - packed/protected artifact(s) detected." >&2
  echo "disrobe-gate: inspect with 'disrobe auto <file> --json', or skip with SKIP=disrobe git commit." >&2
fi
if [ "${analysis_failed}" -ne 0 ]; then
  echo "disrobe-gate: commit blocked - analysis did not complete for every staged file." >&2
fi
exit "${status}"
