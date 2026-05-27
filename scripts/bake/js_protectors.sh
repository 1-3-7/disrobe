#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/corpus/javascript/protectors"
mkdir -p "$OUT_DIR/jsdefender" "$OUT_DIR/arxan" "$OUT_DIR/pace"

cat > "$OUT_DIR/jsdefender/synthesized.js" <<'EOF'
/* PreEmptive Solutions JSDefender (synthesized fixture; mimics PreEmptive published preset; no PreEmptive licensee output used) */
var _PreEmptive_strs = ['hello', 'world', 'foo', 'bar', 'baz'];
function _PreEmptive_decode(i) { return _PreEmptive_strs[i]; }
var state = 0;
while (state !== 3) {
  switch (state) {
    case 0: var a = _PreEmptive_decode(0); state = 1; break;
    case 1: var b = _PreEmptive_decode(1); state = 2; break;
    case 2: console.log(a + ' ' + b); state = 3; break;
  }
}
if (!![]) { console.log('alive'); }
if (![]) { console.log('dead unreachable'); }
EOF

cat > "$OUT_DIR/arxan/synthesized.js" <<'EOF'
/* (c) Digital.ai Application Protection — synthesized fixture, mimics CVE-2024 public disclosure (no Arxan licensee output used) */
function __guard_abc123def() {
  var k = atob('Q2hlY2tzdW1HdWFyZFRva2VuQUFBQQ==');
  return k.length;
}
var data = [1, 2, 3, 4, 5];
for (var __chk = 0; __chk < data.length; __chk++) { data[__chk] ^= 0x42; }
if (__arxan_integrity() !== 0xdeadbeef) { throw new Error('tamper'); }
function realWork() { return 42; }
EOF

cat > "$OUT_DIR/pace/synthesized.js" <<'EOF'
/* PACE Anti-Piracy Fusion (synthesized fixture, mimics public PACE documentation; no PACE licensee output used) */
if (window['__PACE__'] === undefined) { location.reload(); }
setInterval(function () { if (!__PACE__.alive()) { __PACE__.kill(); } }, 5000);
var ilok_token = 'redacted-ilok-bind-id';
function realWork() { return 'unrelated business logic'; }
EOF

cat > "$OUT_DIR/README.md" <<'EOF'
# JS protector fixtures

All files in this tree are **synthesized recreations** generated from publicly available vendor documentation, security-research papers, and CVE disclosures. No file in this tree is the output of a real PreEmptive JSDefender, Digital.ai Arxan, or PACE Anti-Piracy build by a licensee.

Educational/recreation-only per legal stance:
- `jsdefender/` — docs/legal/jsdefender-stance.md (AMBER-leaning-GREEN)
- `arxan/` — docs/legal/digital-ai-arxan-stance.md (AMBER, detect-default, strip behind --i-have-authorization for publicly-documented patterns only)
- `pace/` — docs/legal/pace-js-stance.md (AMBER, DETECT-ONLY, no bypass under any flag)

Regenerate via `scripts/bake/js_protectors.{ps1,sh}`.
EOF

echo "synthesized fixtures written to $OUT_DIR"
