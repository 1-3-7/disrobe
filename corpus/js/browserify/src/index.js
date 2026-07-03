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
