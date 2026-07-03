async function combinators() {
    const slow = (v, ms) => new Promise((r) => setTimeout(() => r(v), ms));
    const reject = (v, ms) => new Promise((_, r) => setTimeout(() => r(new Error(v)), ms));

    const allOut = await Promise.all([slow(1, 1), slow(2, 1), slow(3, 1)]);
    const settledOut = await Promise.allSettled([slow(4, 1), reject("e1", 1), slow(5, 1)]);
    const raceOut = await Promise.race([slow("first", 1), slow("second", 5)]);
    let anyOut;
    try { anyOut = await Promise.any([reject("a", 1), slow("won", 1)]); }
    catch (e) { anyOut = `agg:${e.errors.length}`; }

    return {
        all: allOut,
        settled: settledOut.map((r) => r.status),
        race: raceOut,
        any: anyOut,
    };
}

combinators().then((r) => console.log(r));
