#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/disrobe-action-run-tests.XXXXXX")"
trap 'rm -rf "${scratch}"' EXIT

action_script="${scratch}/run-action.sh"
awk '
  $0 == "      id: run" { in_step = 1 }
  in_step && $0 == "      run: |" { in_run = 1; next }
  in_run && /^    - name:/ { exit }
  in_run && NF && !/^        / { print "invalid run-step indentation" > "/dev/stderr"; exit 1 }
  in_run { sub(/^        /, ""); print }
' "${root}/action.yml" >"${action_script}"
test -s "${action_script}"
chmod +x "${action_script}"
upload_guard="$(grep -F "steps.run.outputs.sarif != ''" "${root}/action.yml")"
case "${upload_guard}" in
  *'always()'*) ;;
  *)
    printf 'SARIF upload must remain eligible after a recovery-threshold failure\n' >&2
    exit 1
    ;;
esac

stub="${scratch}/disrobe-stub"
cat >"${stub}" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "context" ]; then
  printf '%s\n' "${STUB_CONTEXT_MARKER:-}" >&2
  exit 0
fi
case "${STUB_MODE}" in
  valid-zero)
    printf '%s\n' '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"disrobe"}},"results":[]}]}'
    ;;
  valid-findings)
    printf '%s\n' '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"disrobe"}},"results":[{"ruleId":"first","message":{"text":"first finding"}},{"ruleId":"second","message":{"text":"second finding"}}]}]}'
    ;;
  valid-recovery)
    mkdir -p "${DR_OUT}"
    printf '{}\n' >"${DR_OUT}/recovery.json"
    printf '%s\n' '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"disrobe"}},"results":[]}]}'
    ;;
  missing)
    ;;
  invalid-json)
    printf '{not-json\n'
    ;;
  wrong-schema)
    printf '%s\n' '{"$schema":"https://example.test/not-sarif.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"disrobe"}},"results":[]}]}'
    ;;
  failure)
    printf 'deterministic analyzer failure\n' >&2
    exit 17
    ;;
  *)
    printf 'unknown stub mode: %s\n' "${STUB_MODE}" >&2
    exit 64
    ;;
esac
STUB
chmod +x "${stub}"

mkdir -p "${scratch}/bin"
cat >"${scratch}/bin/python3" <<'PYTHON'
#!/usr/bin/env bash
exec python "$@"
PYTHON
chmod +x "${scratch}/bin/python3"

mkdir -p "${scratch}/no-python-bin"
for tool in bash grep mkdir; do
  cat >"${scratch}/no-python-bin/${tool}" <<TOOL
#!/bin/bash
exec /bin/${tool} "\$@"
TOOL
  chmod +x "${scratch}/no-python-bin/${tool}"
done

run_case() {
  local name="$1"
  local mode="$2"
  local fail_on="$3"
  local expected_status="$4"
  local expected_text="$5"
  local context_marker="${6:-}"
  local python_path="${7:-${scratch}/bin:${PATH}}"
  local case_dir="${scratch}/${name}"
  local actual_status=0
  mkdir -p "${case_dir}"
  : >"${case_dir}/github-output"
  : >"${case_dir}/step-summary"
  (
    cd "${case_dir}"
    STUB_MODE="${mode}" \
    STUB_CONTEXT_MARKER="${context_marker}" \
    DR_COMMAND=auto \
    DR_ARGS='' \
    DR_PATH="benign fixture.bin" \
    DR_OUT="${case_dir}/out" \
    DR_SARIF="${case_dir}/disrobe.sarif" \
    DR_FAIL_ON="${fail_on}" \
    DR_BIN="${stub}" \
    GITHUB_OUTPUT="${case_dir}/github-output" \
    GITHUB_STEP_SUMMARY="${case_dir}/step-summary" \
    PATH="${python_path}" \
    bash "${action_script}"
  ) >"${case_dir}/output" 2>&1 || actual_status=$?
  if [ "${actual_status}" -ne "${expected_status}" ]; then
    printf '%s: expected exit %s, got %s\n' "${name}" "${expected_status}" "${actual_status}" >&2
    cat "${case_dir}/output" >&2
    return 1
  fi
  if ! grep -Fq "${expected_text}" "${case_dir}/output" "${case_dir}/github-output" "${case_dir}/step-summary"; then
    printf '%s: missing expected text: %s\n' "${name}" "${expected_text}" >&2
    cat "${case_dir}/output" >&2
    cat "${case_dir}/github-output" >&2
    cat "${case_dir}/step-summary" >&2
    return 1
  fi
  case "${name}" in
    valid-zero|valid-findings|fail-on-incomplete|below-failed-threshold)
      if ! grep -Fq "sarif=${case_dir}/disrobe.sarif" "${case_dir}/github-output"; then
        printf '%s: validated SARIF output was not published\n' "${name}" >&2
        return 1
      fi
      ;;
    *)
      if grep -q '^sarif=' "${case_dir}/github-output"; then
        printf '%s: invalid SARIF path was published\n' "${name}" >&2
        return 1
      fi
      ;;
  esac
  case "${mode}" in
    missing|failure)
      if [ -s "${case_dir}/disrobe.sarif" ]; then
        printf '%s: missing output was replaced with SARIF\n' "${name}" >&2
        return 1
      fi
      ;;
    invalid-json)
      if [ "$(cat "${case_dir}/disrobe.sarif")" != '{not-json' ]; then
        printf '%s: malformed output was replaced\n' "${name}" >&2
        return 1
      fi
      ;;
    wrong-schema)
      if ! grep -Fq 'https://example.test/not-sarif.json' "${case_dir}/disrobe.sarif"; then
        printf '%s: wrong-schema output was replaced\n' "${name}" >&2
        return 1
      fi
      ;;
  esac
}

run_case valid-zero valid-zero never 0 'sarif-results=0'
run_case valid-findings valid-findings never 0 'sarif-results=2'
run_case missing missing never 1 'did not produce SARIF output'
run_case invalid-json invalid-json never 1 'invalid JSON'
run_case wrong-schema wrong-schema never 1 'unexpected schema identifier'
run_case analyzer-failure failure never 1 'exited with status 17'
run_case missing-python valid-zero never 1 'python3 is required' '' "${scratch}/no-python-bin"
run_case fail-on-incomplete valid-recovery incomplete 1 'meets fail-on threshold incomplete' 'disrobe-verdict: verdict=stalled grade=incomplete result=fail'
run_case below-failed-threshold valid-recovery failed 0 'verdict=incomplete' 'disrobe-verdict: verdict=stalled grade=incomplete result=pass'

printf 'github action run tests passed\n'
