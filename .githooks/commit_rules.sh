banned='oracle|wall|honest|honesty|genuinely|non-circular|adversarial|synthetic|fabricated|false-green|load-bearing|clean-room|sound-reject|bisimulation|revert-to-crash|information-theoretic|robust|seamless|powerful|comprehensive|leverage|utilize'
internal_ref='\b[Tt]-[Pp][0-9]+-[0-9A-Za-z]+\b|\b[Tt][0-9]+-[0-9A-Za-z]+\b|\bD-[0-9]{3}\b|\bREVIEW-[0-9A-Z]+\b'
types='feat|fix|refactor|perf|test|docs|build|ci|chore|style|revert'
emdash=$(printf '\342\200\224')
attribution='co-authored-by:.*(claude|anthropic|openai|chatgpt|gpt|copilot|codex|gemini|llm|\bai\b)|generated (with|by) .*(claude|anthropic|chatgpt|gpt|copilot|codex|gemini|llm|\bai\b)|noreply@anthropic\.com'

check_message() {
  label=$1
  file=$2
  subject=$(sed -n '1p' "$file")
  body=$(grep -v '^#' "$file")
  failed=0

  if ! printf '%s\n' "$subject" | grep -qE "^($types)\([a-z0-9][a-z0-9._-]*\)!?: [a-z0-9]"; then
    echo "$label: the subject must be a Conventional Commit with a module scope and a lowercase description, e.g. 'fix(pass-lua): bound constant pool reads'" >&2
    failed=1
  fi

  if [ "${#subject}" -gt 72 ]; then
    echo "$label: the subject is ${#subject} characters; the limit is 72" >&2
    failed=1
  fi

  case "$subject" in
    *.) echo "$label: the subject ends with a period" >&2; failed=1 ;;
  esac

  hit=$(printf '%s\n' "$subject" | grep -oiE "$banned" | head -n 1)
  if [ -n "$hit" ]; then
    echo "$label: '$hit' reads as internal jargon or filler in a public log" >&2
    failed=1
  fi

  hit=$(printf '%s\n' "$body" | grep -oE "$internal_ref" | head -n 1)
  if [ -n "$hit" ]; then
    echo "$label: '$hit' is an internal task or decision reference; commit messages describe the change only" >&2
    failed=1
  fi

  if printf '%s\n' "$body" | grep -qF "$emdash"; then
    echo "$label: em dash in the message" >&2
    failed=1
  fi

  hit=$(printf '%s\n' "$body" | grep -iE "$attribution" | head -n 1)
  if [ -n "$hit" ]; then
    echo "$label: tool or model attribution: $hit" >&2
    failed=1
  fi

  if [ "$failed" -ne 0 ]; then
    echo "  subject: $subject" >&2
  fi
  return $failed
}
