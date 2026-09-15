
/* (c) PreEmptive Solutions, JSDefender preset: control-flow + strings + dead-code */
var _PreEmptive_strs = [
  'hello',
  'world',
  'edge_case',
  'top_level_await',
  'class_fields',
  'optional_chain',
  'nullish_coalesce',
  'private_method',
  'logical_assign',
  'numeric_sep',
];
function _PreEmptive_decode(i) {
  return _PreEmptive_strs[i ^ 0];
}
function __JSD__shift(arr, n) {
  while (--n) arr.push(arr.shift());
}
__JSD__shift(_PreEmptive_strs, 0x3);
var __JSD__state = 0;
while (__JSD__state !== 9) {
  switch (__JSD__state) {
    case 0:
      var a = _PreEmptive_decode(0);
      __JSD__state = 1;
      break;
    case 1:
      var b = _PreEmptive_decode(1);
      __JSD__state = 2;
      break;
    case 2:
      var c = _PreEmptive_decode(2);
      __JSD__state = 3;
      break;
    case 3:
      console.log(a + ' ' + b);
      __JSD__state = 4;
      break;
    case 4:
      console.log(c);
      __JSD__state = 5;
      break;
    case 5:
      var d = _PreEmptive_decode(3);
      __JSD__state = 6;
      break;
    case 6:
      var e = _PreEmptive_decode(4);
      __JSD__state = 7;
      break;
    case 7:
      console.log(d + '/' + e);
      __JSD__state = 8;
      break;
    case 8:
      __JSD__state = 9;
      break;
  }
}
if (!![]) {
  console.log('alive-1');
}
if (![]) {
  console.log('dead-1');
}
if (!![]) {
  console.log('alive-2');
}
if (![]) {
  console.log('dead-2');
}
if (true) {
  console.log('alive-3');
}
function realWork(x) {
  return x + 1;
}
