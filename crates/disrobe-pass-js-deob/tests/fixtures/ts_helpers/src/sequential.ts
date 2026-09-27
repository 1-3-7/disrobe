function delay<T>(value: T): Promise<T> {
    return new Promise((resolve) => setTimeout(() => resolve(value), 0));
}

async function add(a: number, b: number): Promise<number> {
    const left = await delay(a);
    const right = await delay(b);
    return left + right;
}

async function chain(start: number): Promise<string> {
    const first = await add(start, 1);
    const second = await add(first, first);
    const third = await Promise.resolve(second * 3);
    return "chain " + start + " -> " + first + "," + second + "," + third;
}

async function noAwait(label: string): Promise<string> {
    return "plain " + label;
}

async function main(): Promise<void> {
    console.log(await add(2, 3));
    console.log(await chain(4));
    console.log(await noAwait("x"));
    const values = await Promise.all([add(1, 1), add(2, 2), chain(0)]);
    console.log(values.join("|"));
}

main();

export {};
