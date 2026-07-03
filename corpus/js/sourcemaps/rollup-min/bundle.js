function add(a, b) {
	return a + b;
}
const sub = (a, b) => a - b;

function greet(who) {
  return `Hello, ${who}! \u2014 caf\u00e9`;
}

const total = add(sub(10, 4), 3);
console.log(greet('w\u00f6rld'), total);
//# sourceMappingURL=bundle.js.map
