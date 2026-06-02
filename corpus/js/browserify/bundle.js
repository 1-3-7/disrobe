(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const { greet, repeat, Counter } = require("./util.js");
const { sum, factorial } = require("./math.js");

const counter = new Counter();
counter.inc();
counter.inc();

console.log(
  JSON.stringify({
    banner: repeat(greet("world"), 2),
    counter: counter.value,
    sum: sum([1, 2, 3, 4, 5]),
    factorial: factorial(5),
  }),
);

},{"./math.js":2,"./util.js":3}],2:[function(require,module,exports){
const add = (a, b) => a + b;
const mul = (a, b) => a * b;
const sum = (xs) => xs.reduce(add, 0);
const factorial = (n) => (n <= 1 ? 1 : mul(n, factorial(n - 1)));
module.exports = { add, mul, sum, factorial };

},{}],3:[function(require,module,exports){
const greet = (name) => `hello ${name}`;
const repeat = (s, n) => Array(n).fill(s).join(" ");
class Counter {
  constructor() {
    this._count = 0;
  }
  inc() {
    this._count += 1;
    return this._count;
  }
  get value() {
    return this._count;
  }
}
module.exports = { greet, repeat, Counter };

},{}]},{},[1]);
