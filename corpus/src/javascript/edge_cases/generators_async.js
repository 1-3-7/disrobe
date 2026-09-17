function* fibonacci() {
    let a = 0n;
    let b = 1n;
    while (true) {
        yield a;
        [a, b] = [b, a + b];
    }
}

async function* ticker(values) {
    for (const v of values) {
        await Promise.resolve();
        yield { tick: v };
    }
}

async function main() {
    const fib = fibonacci();
    const first = [];
    for (let i = 0; i < 8; i++) {
        first.push(fib.next().value);
    }
    const ticks = [];
    for await (const t of ticker([10, 20, 30])) {
        ticks.push(t);
    }
    return { first: first.map(String), ticks };
}

main().then((r) => console.log(JSON.stringify(r)));
