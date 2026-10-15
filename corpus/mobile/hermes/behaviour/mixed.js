function f(a, b) {
  var s = 0;
  for (var i = a; i < b; i++) {
    if (i % 2 === 0) s += i; else s -= 1;
  }
  return s;
}
function P(x) { this.x = x; }
P.prototype.double = function () { return this.x * 2; };
P.make = function (v) { return new P(v); };
P.prototype.toString = function () { return `P(${this.x})`; };
function g(k) {
  switch (k) {
    case 1: return 'one';
    case 2: return 'two';
    default: return 'many';
  }
}
function h() {
  try { throw new Error('boom'); } catch (e) { return e.message; } finally { print('fin'); }
}
var counter = (function () { var c = 0; return function () { return ++c; }; })();
print(f(1, 10), g(2), h(), counter(), counter(), String(P.make(21)), P.make(4).double());
print(/a+b/g.test('xaab'), [3, 1, 2].sort().join(','), typeof null);
let arrow = (x, y) => x + y;
const [q, ...rest] = [1, 2, 3];
const { k1, k2 = 5 } = { k1: 9 };
print(arrow(1, 2), q, rest.length, k1, k2);
for (const v of [10, 20]) { print(v); }
function* gen() { yield 1; yield 2; }
var it = gen();
print(it.next().value, it.next().value, it.next().done);
async function af() { return 7; }
af().then(function (v) { print('async', v); });
label1: for (var i = 0; i < 3; i++) { for (var j = 0; j < 3; j++) { if (j === 1) continue label1; print(i, j); } }
var obj = { a: 1, b: 2, ['c' + 1]: 3 };
print(JSON.stringify(obj), Object.keys(obj).length);
