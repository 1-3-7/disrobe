function add(a, b) {
  return a + b;
}

function sumRange(n) {
  var total = 0;
  for (var i = 1; i <= n; i = i + 1) {
    total = total + i;
  }
  return total;
}

function greet(name) {
  var prefix = "disrobe-hermes-";
  return prefix + name + "!";
}

function Counter(start) {
  this.value = start;
}

Counter.prototype.increment = function increment() {
  this.value = this.value + 1;
  return this.value;
};

Counter.prototype.label = function label() {
  return greet("counter-" + this.value);
};

function main() {
  var c = new Counter(add(2, 3));
  c.increment();
  globalThis.print(c.label());
  globalThis.print(sumRange(10));
  return c.value;
}

main();
