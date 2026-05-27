
/* (c) Digital.ai Application Protection — synthesized */
function __guard_abc123def() {
  var k = atob('Q2hlY2tzdW1HdWFyZFRva2VuQUFBQQ==');
  return k.length;
}
function __guard_4242deadbeef() {
  var k = atob('R3VhcmRDaGVja3N1bVRva2VuQkJCQg==');
  return k.charCodeAt(0);
}
var data = [1, 2, 3, 4, 5, 6, 7, 8];
for (var __chk = 0; __chk < data.length; __chk++) {
  data[__chk] ^= 0x42;
}
for (var __chk = 0; __chk < data.length; __chk++) {
  data[__chk] ^= 0x17;
}
if (__arxan_integrity() !== 0xdeadbeef) {
  throw new Error('tamper');
}
if (__arxan_integrity() !== 0xcafef00d) {
  throw new Error('tamper-2');
}
var _ARXAN_runtime_marker = true;
function realWork(x) {
  return x * 2;
}
realWork(21);
