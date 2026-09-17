#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/disrobe-gate-tests.XXXXXX")"
trap 'rm -rf "${scratch}"' EXIT

mkdir -p "${scratch}/bin" "${scratch}/tmp"
input="${scratch}/staged file.bin"
printf 'harmless fixture\n' >"${input}"

cat >"${scratch}/bin/disrobe-stand-in" <<'EOF'
#!/usr/bin/env bash
case "${STANDIN_RESULT:?}" in
  clean)
    printf '{"schema":"disrobe.chain/v1","tool_version":"test","input":{"path":"fixture","blake3":"0000000000000000000000000000000000000000000000000000000000000000","size":17,"detected":[]},"spec":{"raw":"auto","kind":"auto","cap":8},"topology":"linear","root_node_id":0,"nodes":[{"id":0,"parent_id":null,"depth":0,"branch_id":"root","pass":null,"format_tag_in":null,"input_blake3":"0000000000000000000000000000000000000000000000000000000000000000","input_size":17,"output_kind":null,"output_blake3":null,"output_size":null,"duration_ms":null,"detector_picks":[],"artifacts":[],"metadata":{},"rule_pack_id":null,"verdict":"ok","error":null}],"verdict":"ok","final_format":null,"stats":{"layers":1,"branches":1,"total_ms":0,"max_branch_depth":0,"detector_calls":0,"rejected_passes":0}}\n'
    ;;
  empty)
    printf '{"schema":"disrobe.chain/v1","nodes":[]}\n'
    ;;
  blocked)
    printf '{"nodes":[{"detector_picks":[{"chosen":true,"pass_id":"native.packer-unpack","family":"packer-archive"}]}]}\n'
    ;;
  failure)
    printf 'stand-in analyzer failure\n' >&2
    exit 17
    ;;
  malformed)
    printf '{not-json\n'
    ;;
  missing)
    ;;
  missing-nodes)
    printf '{}\n'
    ;;
  wrong-nodes)
    printf '{"nodes":{}}\n'
    ;;
  wrong-node)
    printf '{"nodes":[7]}\n'
    ;;
  missing-picks)
    printf '{"nodes":[{}]}\n'
    ;;
  wrong-picks)
    printf '{"nodes":[{"detector_picks":{}}]}\n'
    ;;
  wrong-pick)
    printf '{"nodes":[{"detector_picks":[7]}]}\n'
    ;;
  missing-chosen)
    printf '{"nodes":[{"detector_picks":[{"pass_id":"other","family":"other"}]}]}\n'
    ;;
  wrong-chosen)
    printf '{"nodes":[{"detector_picks":[{"chosen":"false","pass_id":"other","family":"other"}]}]}\n'
    ;;
  missing-pass-id)
    printf '{"nodes":[{"detector_picks":[{"chosen":false,"family":"other"}]}]}\n'
    ;;
  wrong-pass-id)
    printf '{"nodes":[{"detector_picks":[{"chosen":false,"pass_id":7,"family":"other"}]}]}\n'
    ;;
  missing-family)
    printf '{"nodes":[{"detector_picks":[{"chosen":false,"pass_id":"other"}]}]}\n'
    ;;
  wrong-family)
    printf '{"nodes":[{"detector_picks":[{"chosen":false,"pass_id":"other","family":7}]}]}\n'
    ;;
esac
EOF
chmod +x "${scratch}/bin/disrobe-stand-in"

if ! python3 --version >/dev/null 2>&1; then
  cat >"${scratch}/bin/python3" <<'EOF'
#!/usr/bin/env bash
exec python "$@"
EOF
  chmod +x "${scratch}/bin/python3"
fi

failures=0
run_case() {
  local name="$1"
  local expected_status="$2"
  local expected_message="$3"
  local second_message="${4:-}"
  local actual_status=0
  local output="${scratch}/${name}.log"

  STANDIN_RESULT="${name}" \
    DISROBE_BIN="${scratch}/bin/disrobe-stand-in" \
    TMPDIR="${scratch}/tmp" \
    PATH="${scratch}/bin:${PATH}" \
    "${root}/hooks/pre-commit-gate.sh" "${input}" >"${output}" 2>&1 || actual_status=$?

  if [ "${actual_status}" -ne "${expected_status}" ]; then
    printf '%s: expected exit %s, got %s\n' "${name}" "${expected_status}" "${actual_status}" >&2
    failures=$((failures + 1))
  fi
  if [ -n "${expected_message}" ] && ! grep -Fq "${expected_message}" "${output}"; then
    printf '%s: missing output %s\n' "${name}" "${expected_message}" >&2
    failures=$((failures + 1))
  fi
  if [ -n "${second_message}" ] && ! grep -Fq "${second_message}" "${output}"; then
    printf '%s: missing output %s\n' "${name}" "${second_message}" >&2
    failures=$((failures + 1))
  fi
  if [ "${actual_status}" -eq 0 ] && [ -s "${output}" ]; then
    printf '%s: successful analysis produced unexpected output\n' "${name}" >&2
    failures=$((failures + 1))
  fi
  if find "${scratch}/tmp" -mindepth 1 -maxdepth 1 -name 'disrobe-gate.*' -print -quit | grep -q .; then
    printf '%s: hook left temporary output behind\n' "${name}" >&2
    failures=$((failures + 1))
  fi
}

run_case clean 0 ""
run_case empty 0 ""
run_case blocked 1 "disrobe-gate: BLOCKED"
run_case failure 1 "analyzer exited 17" "stand-in analyzer failure"
run_case malformed 1 "invalid JSON report"
run_case missing 1 "produced no JSON report"
run_case missing-nodes 1 "invalid JSON report" "report must contain nodes"
run_case wrong-nodes 1 "invalid JSON report" "report nodes must be an array"
run_case wrong-node 1 "invalid JSON report" "each report node must be an object"
run_case missing-picks 1 "invalid JSON report" "report node must contain detector_picks"
run_case wrong-picks 1 "invalid JSON report" "detector_picks must be an array"
run_case wrong-pick 1 "invalid JSON report" "each detector pick must be an object"
run_case missing-chosen 1 "invalid JSON report" "detector pick must contain chosen"
run_case wrong-chosen 1 "invalid JSON report" "detector pick chosen must be a boolean"
run_case missing-pass-id 1 "invalid JSON report" "detector pick must contain pass_id"
run_case wrong-pass-id 1 "invalid JSON report" "detector pick pass_id must be a string"
run_case missing-family 1 "invalid JSON report" "detector pick must contain family"
run_case wrong-family 1 "invalid JSON report" "detector pick family must be a string"

cat >"${scratch}/bin/python-selected" <<'EOF'
#!/usr/bin/env bash
printf 'selected\n' >"${DR_PYTHON_PROBE}"
exec python3 "$@"
EOF
chmod +x "${scratch}/bin/python-selected"
DISROBE_PYTHON="${scratch}/bin/python-selected" DR_PYTHON_PROBE="${scratch}/python-probe" run_case clean 0 ""
if [ ! -s "${scratch}/python-probe" ]; then
  printf 'explicit Python interpreter was not used\n' >&2
  failures=$((failures + 1))
fi

if [ "${failures}" -ne 0 ]; then
  exit 1
fi

printf 'pre-commit gate tests passed\n'
