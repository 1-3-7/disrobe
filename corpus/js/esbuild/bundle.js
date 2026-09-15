var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/lazy.js
var lazy_exports = {};
__export(lazy_exports, {
  heavyTag: () => heavyTag,
  lazyCompute: () => lazyCompute
});
var heavyTag, lazyCompute;
var init_lazy = __esm({
  "src/lazy.js"() {
    heavyTag = "lazy-loaded:" + String(Math.random()).slice(2, 8);
    lazyCompute = (x) => x ** 2 + x + 1;
  }
});

// src/util.js
var greet = (name) => `hello ${name}`;
var repeat = (s, n) => Array(n).fill(s).join(" ");
var Counter = class {
  #count = 0;
  inc() {
    this.#count += 1;
    return this.#count;
  }
  get value() {
    return this.#count;
  }
};

// src/math.js
var add = (a, b) => a + b;
var mul = (a, b) => a * b;
var sum = (xs) => xs.reduce(add, 0);
var factorial = (n) => n <= 1 ? 1 : mul(n, factorial(n - 1));

// src/index.js
var counter = new Counter();
counter.inc();
counter.inc();
var greeting = greet("world");
var banner = repeat(greeting, 2);
console.log(
  JSON.stringify({
    banner,
    counter: counter.value,
    sum: sum([1, 2, 3, 4, 5]),
    factorial: factorial(5)
  })
);
async function loadLazy() {
  const mod = await Promise.resolve().then(() => (init_lazy(), lazy_exports));
  console.log(mod.heavyTag, mod.lazyCompute(3));
}
loadLazy().catch(console.error);
//# sourceMappingURL=bundle.js.map
