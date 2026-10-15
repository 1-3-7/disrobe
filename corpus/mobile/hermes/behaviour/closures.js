function makeCounter(start) {
  var count = start;
  return {
    inc: function () { return ++count; },
    dec: function () { return count--; },
    get: function () { return count; }
  };
}

function adders() {
  var fns = [];
  for (var i = 0; i < 4; i++) {
    fns.push((function (n) { return function (x) { return x + n; }; })(i));
  }
  return fns.map(function (f) { return f(10); }).join(',');
}

function fact(n) { return n <= 1 ? 1 : n * fact(n - 1); }
function isEven(n) { return n === 0 ? true : isOdd(n - 1); }
function isOdd(n) { return n === 0 ? false : isEven(n - 1); }

function variadic() {
  var parts = [];
  for (var i = 0; i < arguments.length; i++) parts.push(typeof arguments[i]);
  return arguments.length + ':' + parts.join('/');
}

function defaults(a, b = a * 2, ...rest) {
  return [a, b, rest.length, rest.join('+')].join(' ');
}

function outer() {
  var x = 1;
  function middle() {
    var y = 2;
    function inner() {
      x += 10;
      y += 20;
      return x + y;
    }
    return inner() + inner();
  }
  return middle() + x;
}

var arrow = (a, b) => a * b + (this === undefined ? 0 : 1);
var compose = function (f, g) { return function (v) { return f(g(v)); }; };
var twice = compose(function (v) { return v * 2; }, function (v) { return v + 3; });

var c = makeCounter(5);
print(c.inc(), c.inc(), c.dec(), c.dec(), c.get());
print(adders());
print(fact(10), isEven(10), isOdd(7));
print(variadic(1, 'a', null, {}, [], undefined), variadic());
print(defaults(1), defaults(1, 5), defaults(1, 2, 3, 4, 5));
print(outer());
print(arrow(3, 4), twice(4), Math.max.apply(null, [3, 9, 4]));
var nums = [5, 1, 4];
print(Math.min(...nums), [...nums, 7].length, String.fromCharCode(...[72, 105]));
print((function () { return typeof this; })(), (function () { 'use strict'; return typeof this; })());
