var proto = { greet: function () { return 'hi ' + this.name; } };
var key = 'dyn';
var obj = {
  name: 'obj',
  count: 3,
  [key + 'amic']: true,
  nested: { deep: [1, 2, { x: 'y' }] },
  get double() { return this.count * 2; },
  set double(v) { this.count = v / 2; },
  method() { return this.name.toUpperCase(); },
  __proto__: proto
};
print(obj.greet(), obj.double, obj.method(), obj.dynamic, obj.nested.deep[2].x);
obj.double = 10;
print(obj.count, Object.keys(obj).join(','), 'greet' in obj, obj.hasOwnProperty('greet'));

var holes = [1, , 3];
holes[6] = 7;
print(holes.length, 1 in holes, holes.join('-'));
var spread = [0, ...holes.slice(0, 3), 9];
print(spread.length, JSON.stringify(spread));

var { name, count: renamed, missing = 'dflt', ...others } = obj;
print(name, renamed, missing, Object.keys(others).join(','));
var [first, , third = 'T', ...tail] = ['a', 'b', undefined, 'd', 'e'];
print(first, third, tail.join(''));
function swap(pair) { var [a, b] = pair; return [b, a]; }
print(swap([1, 2]).join(','));

var bag = { a: 1, b: 2, c: 3, d: 4 };
var seen = [];
for (var k in bag) {
  if (k === 'b') delete bag.c;
  seen.push(k + '=' + bag[k]);
}
print(seen.join(' '));
for (var idx in ['x', 'y']) print('idx', idx, typeof idx);
var total = 0;
for (var v of [3, 4, 5]) total += v;
for (var ch of 'abc') total += ch.charCodeAt(0);
print(total);
var m = new Map([[1, 'one'], [2, 'two']]);
for (var [mk, mv] of m) print(mk, mv);
print(typeof undeclaredGlobal, typeof obj, typeof null, typeof print, typeof 1n);
print(delete obj.name, obj.name, delete obj.nothing, [] instanceof Array, obj instanceof Object);
function Point(x, y) { this.x = x; this.y = y; }
Point.prototype.len = function () { return Math.sqrt(this.x * this.x + this.y * this.y); };
var p = new Point(3, 4);
function Factory() { return { made: true }; }
print(p.len(), p instanceof Point, new Factory().made, new Factory() instanceof Factory);
var frozen = Object.freeze({ z: 1 });
print(Object.isFrozen(frozen), JSON.stringify({ a: [1, { b: null }], c: 'd' }), JSON.parse('{"q":[1,2]}').q[1]);
