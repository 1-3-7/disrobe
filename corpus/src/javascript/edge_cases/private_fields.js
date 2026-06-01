class Counter {
    #value = 0;
    static #instances = 0;

    constructor(initial = 0) {
        this.#value = initial;
        Counter.#instances += 1;
    }

    increment() {
        this.#value += 1;
        return this;
    }

    get value() {
        return this.#value;
    }

    static get instanceCount() {
        return Counter.#instances;
    }

    static #isCounter(obj) {
        return #value in obj;
    }

    static checkSibling(obj) {
        return Counter.#isCounter(obj);
    }
}

const a = new Counter(10).increment().increment();
const b = new Counter(0).increment();
console.log({
    a: a.value,
    b: b.value,
    total: Counter.instanceCount,
    sibling: Counter.checkSibling(a),
    foreign: Counter.checkSibling({}),
});
