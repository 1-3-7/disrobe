const sab = new SharedArrayBuffer(16);
const view = new Int32Array(sab);

Atomics.store(view, 0, 100);
Atomics.add(view, 0, 5);
Atomics.or(view, 1, 0xff);
const compareSwap = Atomics.compareExchange(view, 0, 105, 200);
const finalLoad = Atomics.load(view, 0);
const hasWaitAsync = typeof Atomics.waitAsync === "function";

console.log({ compareSwap, finalLoad, hasWaitAsync, secondSlot: view[1] });
