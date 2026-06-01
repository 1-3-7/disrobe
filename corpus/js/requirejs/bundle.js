define('app/index', (function () { 'use strict';

  const greet = (name) => `hello ${name}`;
  const repeat = (s, n) => Array(n).fill(s).join(" ");
  class Counter {
    #count = 0;
    inc() {
      this.#count += 1;
      return this.#count;
    }
    get value() {
      return this.#count;
    }
  }

  const add = (a, b) => a + b;
  const mul = (a, b) => a * b;
  const sum = (xs) => xs.reduce(add, 0);
  const factorial = (n) => (n <= 1 ? 1 : mul(n, factorial(n - 1)));

  const counter = new Counter();
  counter.inc();
  counter.inc();

  const greeting = greet("world");
  const banner = repeat(greeting, 2);

  console.log(
    JSON.stringify({
      banner,
      counter: counter.value,
      sum: sum([1, 2, 3, 4, 5]),
      factorial: factorial(5),
    }),
  );

  async function loadLazy() {
    const mod = await Promise.resolve().then(function () { return lazy; });
    console.log(mod.heavyTag, mod.lazyCompute(3));
  }

  loadLazy().catch(console.error);

  const heavyTag = "lazy-loaded:" + String(Math.random()).slice(2, 8);
  const lazyCompute = (x) => x ** 2 + x + 1;

  var lazy = /*#__PURE__*/Object.freeze({
    __proto__: null,
    heavyTag: heavyTag,
    lazyCompute: lazyCompute
  });

}));
//# sourceMappingURL=bundle.js.map
