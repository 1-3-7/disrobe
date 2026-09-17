#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
jars="$here/jars"
mkdir -p "$jars"

only="all"
if [[ "${1:-}" == "--only" && -n "${2:-}" ]]; then only="$2"; fi

JADX_VERSION="1.5.5"
CFR_VERSION="0.152"
APKLEAKS_VERSION="2.6.3"
CFR_SHA256="f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2"

fetch() { curl -fsSL --retry 3 -o "$1" "$2"; }

verify_sha256() {
  local file="$1" want="$2"
  local got
  got="$(sha256sum "$file" | cut -d' ' -f1)"
  if [[ "$got" != "$want" ]]; then
    echo "SHA-256 mismatch for $file: got $got want $want" >&2
    exit 1
  fi
}

install_jadx() {
  if command -v jadx >/dev/null 2>&1; then echo "jadx already on PATH"; return; fi
  echo "installing jadx $JADX_VERSION"
  local tmp; tmp="$(mktemp -d)"
  fetch "$tmp/jadx.zip" "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
  unzip -q "$tmp/jadx.zip" -d "$jars/jadx"
  chmod +x "$jars/jadx/bin/jadx"
  echo "$jars/jadx/bin" >> "${GITHUB_PATH:-/dev/stdout}"
}

install_cfr() {
  echo "installing cfr $CFR_VERSION"
  fetch "$jars/cfr.jar" "https://github.com/leibnitz27/cfr/releases/download/${CFR_VERSION}/cfr-${CFR_VERSION}.jar"
  verify_sha256 "$jars/cfr.jar" "$CFR_SHA256"
}

install_apkleaks() {
  echo "installing apkleaks $APKLEAKS_VERSION"
  python3 -m pip install --user "apkleaks==${APKLEAKS_VERSION}"
}

case "$only" in
  apk)   install_jadx; install_cfr ;;
  frisk) install_jadx; install_apkleaks ;;
  gate)  echo "gate lane needs only the committed corpus + javac (setup-java) + the swift toolchain reference; nothing to install here" ;;
  all)   install_jadx; install_cfr; install_apkleaks ;;
  *) echo "unknown --only target: $only" >&2; exit 2 ;;
esac

echo "competitor install complete (--only $only)"
