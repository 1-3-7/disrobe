function tick(value: number): Promise<number> {
    return new Promise((resolve) => setTimeout(() => resolve(value), 0));
}

async function sumRange(limit: number): Promise<number> {
    let total = 0;
    for (let index = 0; index < limit; index++) {
        total += await tick(index);
    }
    return total;
}

async function countDown(start: number): Promise<string> {
    const seen: number[] = [];
    let current = start;
    while (current > 0) {
        seen.push(await tick(current));
        current -= 2;
    }
    return seen.join(",");
}

async function doWhile(): Promise<number> {
    let rounds = 0;
    do {
        rounds = await tick(rounds + 1);
    } while (rounds < 4);
    return rounds;
}

async function overArray(items: string[]): Promise<string> {
    let out = "";
    for (const item of items) {
        out += (await Promise.resolve(item)).toUpperCase();
    }
    return out;
}

async function skipAndStop(values: number[]): Promise<number> {
    let total = 0;
    for (let index = 0; index < values.length; index++) {
        const value = await tick(values[index]);
        if (value < 0) {
            continue;
        }
        if (value > 100) {
            break;
        }
        total += value;
    }
    return total;
}

async function main(): Promise<void> {
    console.log(await sumRange(5));
    console.log(await countDown(7));
    console.log(await doWhile());
    console.log(await overArray(["a", "b", "c"]));
    console.log(await skipAndStop([1, -2, 3, 400, 5]));
}

main();

export {};
