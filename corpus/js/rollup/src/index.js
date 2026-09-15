import { greet, repeat, Counter } from "./util.js";
import { sum, factorial } from "./math.js";

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
  const mod = await import("./lazy.js");
  console.log(mod.heavyTag, mod.lazyCompute(3));
}

loadLazy().catch(console.error);
