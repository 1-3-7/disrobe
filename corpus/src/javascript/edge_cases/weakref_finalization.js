const registry = new FinalizationRegistry((label) => {
    globalThis.__finalized = (globalThis.__finalized ?? []).concat(label);
});

function track(label) {
    const obj = { label, payload: new Array(8).fill(label) };
    registry.register(obj, label);
    return new WeakRef(obj);
}

const refA = track("alpha");
const refB = track("beta");

console.log({
    aLabel: refA.deref()?.label ?? "gone",
    bLabel: refB.deref()?.label ?? "gone",
    registryType: registry.constructor.name,
});
