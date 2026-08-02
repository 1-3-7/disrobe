#!/usr/bin/env bash
set -euo pipefail

summary="docs/src/SUMMARY.md"
out="${1:-site/llms-full.txt}"
base="https://1-3-7.github.io/disrobe/latest"

{
  echo "# disrobe: full documentation for LLM ingestion"
  echo
  echo "> One tool to decompile, deobfuscate, and unpack compiled software, deterministically, in a single Rust binary. This file concatenates the full disrobe documentation in reading order for retrieval and ingestion. Canonical hosted docs: ${base}/. Source repository: https://github.com/1-3-7/disrobe."
  echo
  echo "Strong recovery claims are measured against independent references. Coverage self-reports are labeled, scoped to their inspected populations, and never presented as external correctness."
  echo
} > "$out"

grep -oE '\]\(\./[^)]+\.md\)' "$summary" | sed -E 's/^\]\(\.\///; s/\)$//' | while IFS= read -r rel; do
  src="docs/src/${rel}"
  [ -f "$src" ] || continue
  url="${base}/${rel%.md}.html"
  {
    echo
    echo "================================================================================"
    echo "Source page: ${url}"
    echo "================================================================================"
    echo
    cat "$src"
    echo
  } >> "$out"
done

lines="$(wc -l < "$out")"
echo "wrote $out ($lines lines)"
