const order: string[] = [];

async function worker(name: string, rounds: number): Promise<string> {
    order.push(name + " start");
    for (let round = 0; round < rounds; round++) {
        await null;
        order.push(name + " round " + round);
    }
    const settled = await Promise.resolve(name.length);
    order.push(name + " settled " + settled);
    return name + " done";
}

async function returnsPromise(): Promise<string> {
    order.push("returnsPromise start");
    return Promise.resolve("inner promise");
}

async function main(): Promise<void> {
    const first = worker("alpha", 2);
    const second = worker("be", 3);
    const third = returnsPromise();
    order.push("sync end");
    const results = await Promise.all([first, second, third]);
    console.log(results.join(","));
    console.log(order.join("\n"));
}

main();

export {};
