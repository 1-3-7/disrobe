#!/usr/bin/env bash
# disrobe pre-commit gate: fail the commit when a staged file is a packed or
# protected artifact, as detected by the disrobe chain auto-router.
#
# Invoked by the pre-commit.com framework with the matched staged files as
# positional arguments. Locate disrobe via $DISROBE_BIN or PATH.
#
# By default it blocks the high-precision packer/protector detectors only
# (unambiguous structural magic, near-zero false positives on source files):
#   $DISROBE_BLOCK_PASSES   default "native.packer-unpack,pyarmor.unpack,
#                           pyinstaller.extract,sourcedefender.decrypt,
#                           nuitka.extract,pyfreeze.extract"
# To additionally block whole detector families (broader, but the source-level
# obfuscation classifiers can false-positive on ordinary text), opt in with:
#   $DISROBE_BLOCK_FAMILIES default "" (e.g. "obfuscator-wrapper,packer-archive")
set -euo pipefail

bin="${DISROBE_BIN:-disrobe}"
block_passes="${DISROBE_BLOCK_PASSES:-native.packer-unpack,pyarmor.unpack,pyinstaller.extract,sourcedefender.decrypt,nuitka.extract,pyfreeze.extract}"
block_families="${DISROBE_BLOCK_FAMILIES:-}"

if ! command -v "${bin}" >/dev/null 2>&1; then
  echo "disrobe-gate: '${bin}' not found on PATH." >&2
  echo "disrobe-gate: install from https://github.com/1-3-7/disrobe/releases or set DISROBE_BIN." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "disrobe-gate: python3 is required to parse the chain report." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  exit 0
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/disrobe-gate.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

status=0
for file in "$@"; do
  [ -f "${file}" ] || continue

  outdir="${workdir}/out"
  report="$("${bin}" auto "${file}" --json --out "${outdir}" 2>/dev/null)" || true
  rm -rf "${outdir}"
  [ -n "${report}" ] || continue

  hit="$(printf '%s' "${report}" | DR_PASSES="${block_passes}" DR_FAMILIES="${block_families}" python3 -c '
import json, os, sys
passes = {p.strip() for p in os.environ.get("DR_PASSES", "").split(",") if p.strip()}
families = {f.strip() for f in os.environ.get("DR_FAMILIES", "").split(",") if f.strip()}
try:
    doc = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
hits = []
for node in doc.get("nodes", []):
    for pick in node.get("detector_picks", []):
        if not pick.get("chosen"):
            continue
        pid = pick.get("pass_id", "?")
        fam = pick.get("family")
        if pid in passes or (fam in families):
            hits.append("{} ({})".format(pid, fam))
if hits:
    print("; ".join(sorted(set(hits))))
')" || true

  if [ -n "${hit}" ]; then
    echo "disrobe-gate: BLOCKED ${file}: ${hit}" >&2
    status=1
  fi
done

if [ "${status}" -ne 0 ]; then
  echo "disrobe-gate: commit blocked - packed/protected artifact(s) detected." >&2
  echo "disrobe-gate: inspect with 'disrobe auto <file> --json', or skip with SKIP=disrobe git commit." >&2
fi
exit "${status}"
