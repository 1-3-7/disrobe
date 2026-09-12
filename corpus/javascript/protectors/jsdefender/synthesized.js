
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
