
function __guard_abc123def() {
  var k = atob('Q2hlY2tzdW1HdWFyZFRva2VuQUFBQQ==');
  return k.length;
}
var data = [1, 2, 3, 4, 5];
for (var __chk = 0; __chk < data.length; __chk++) { data[__chk] ^= 0x42; }
if (__arxan_integrity() !== 0xdeadbeef) { throw new Error('tamper'); }
function realWork() { return 42; }
