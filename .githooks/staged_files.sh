#!/bin/sh
status=0
root_garbage=$(git diff --cached --diff-filter=A --name-only -- ':!*/*' | while read -r f; do
  case "$f" in
    Cargo.toml|Cargo.lock|README.md|NOTICE|LICENSE|LICENSING.md|CONTRIBUTING.md|clippy.toml|deny.toml|rust-toolchain.toml|rustfmt.toml|typos.toml|committed.toml|justfile|lefthook.yml|.gitignore|.gitattributes) ;;
    *) echo "$f" ;;
  esac
done)
if [ -n "$root_garbage" ]; then
  echo "pre-commit: refusing to commit root-level files not on the allowlist: $root_garbage" >&2
  status=1
fi
zero_byte=$(git diff --cached --diff-filter=A --name-only | while read -r f; do
  test -f "$f" || continue
  test -s "$f" || echo "$f"
done)
if [ -n "$zero_byte" ]; then
  echo "pre-commit: refusing to commit zero-byte files: $zero_byte" >&2
  status=1
fi
exit "$status"
