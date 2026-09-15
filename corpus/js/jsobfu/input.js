var COUNT = 0;
function inc() {
  COUNT += 1;
  return COUNT;
}
function greet(name, salutation) {
  return (salutation || "hello") + " " + name + "!";
}
function add(a, b) { return a + b; }
function mul(a, b) { return a * b; }
function fib(n) {
  var a = 0, b = 1, t;
  for (var i = 0; i < n; i++) { t = a + b; a = b; b = t; }
  return a;
}
function factorial(n, acc) {
  if (typeof acc !== "number") acc = 1;
  if (n <= 1) return acc;
  return factorial(n - 1, acc * n);
}
var REGISTRY = {};
function register(name, fn) {
  REGISTRY[name] = fn;
  inc();
  return name;
}
register("greet", greet);
register("add", add);
register("mul", mul);
register("fib", fib);
register("factorial", factorial);
var result = {
  greeting: greet("world", "hi"),
  sum: add(1, 2),
  product: mul(3, 4),
  fib10: fib(10),
  factorial5: factorial(5),
  count: COUNT,
  registered: (function () {
    var keys = [];
    for (var k in REGISTRY) keys.push(k);
    return keys.join(",");
  })()
};
console.log(JSON.stringify(result));
