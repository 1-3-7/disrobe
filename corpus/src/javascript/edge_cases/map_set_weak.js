const map = new Map();
const set = new Set([1, 2, 3, 1, 2]);
const wm = new WeakMap();
const ws = new WeakSet();
const keyA = { id: 1 };
const keyB = { id: 2 };

map.set("a", 1).set("b", 2).set("c", 3);
wm.set(keyA, "metadata-a").set(keyB, "metadata-b");
ws.add(keyA).add(keyB);

const fromEntries = Object.fromEntries(map);
const fromSet = [...set];
const grouped = Map.groupBy([1, 2, 3, 4, 5], (n) => (n % 2 === 0 ? "even" : "odd"));

console.log({
    mapSize: map.size,
    setSize: set.size,
    fromEntries,
    fromSet,
    grouped: { even: grouped.get("even"), odd: grouped.get("odd") },
    hasWeakA: wm.has(keyA),
});
