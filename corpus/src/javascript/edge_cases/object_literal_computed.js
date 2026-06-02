const key = "dynamic";
const counter = (() => { let n = 0; return () => ++n; })();
const base = { static: true };

const literal = {
    ...base,
    [key]: 1,
    [`${key}_${counter()}`]: 2,
    [Symbol.iterator]() {
        let i = 0;
        return { next() { return i++ < 3 ? { value: i, done: false } : { value: undefined, done: true }; } };
    },
    shorthand: counter(),
    method(x) { return x * 2; },
    get total() { return this.shorthand * 10; },
};

console.log({
    keys: Object.keys(literal),
    methodOut: literal.method(7),
    total: literal.total,
    iterated: [...literal],
});
