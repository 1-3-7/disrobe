
/* (c) Digital.ai Application Protection * synthesized build 2024.1 */
function __guard_abc123def() {
  var k = atob('Q2hlY2tzdW1HdWFyZFRva2VuQUFBQQ==');
  return k.length;
}
function __guard_4242deadbeef() {
  var k = atob('R3VhcmRDaGVja3N1bVRva2VuQkJCQg==');
  if (k.length > 1) { return k.charCodeAt(0); }
  return 0;
}
function __guard_5151feedface() {
  var k = atob('U2Vjb25kR3VhcmRUb2tlbkNDQ0ND');
  var acc = 0;
  for (var j = 0; j < k.length; j++) { acc = (acc + k.charCodeAt(j)) & 0xff; }
  return acc;
}
var data = [1, 2, 3, 4, 5, 6, 7, 8];
for (var __chk = 0; __chk < data.length; __chk++) {
  data[__chk] ^= 0x42;
}
for (var __chk = 0; __chk < data.length; __chk++) {
  if (data[__chk] > 4) { data[__chk] ^= 0x17; } else { data[__chk] ^= 0x31; }
}
for (var __chk = 0; __chk < data.length; __chk++) {
  data[__chk] ^= 0x5d;
  var __sep = '}';
}
if (__arxan_integrity() !== 0xdeadbeef) {
  throw new Error('tamper');
}
if (__arxan_integrity() !== 0xcafef00d) {
  if (typeof console !== 'undefined') { console.log('tamper-2'); }
  throw new Error('tamper-2');
}
var _ARXAN_runtime_marker = true;
function realWork(x) {
  return x * 2;
}
realWork(21);
