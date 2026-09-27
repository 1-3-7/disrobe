async function countArgs(first: number, ...rest: number[]): Promise<string> {
    const total = await Promise.resolve(rest.reduce((acc, value) => acc + value, first));
    return "args=" + (rest.length + 1) + " total=" + total;
}

async function withDefault(value: number, scale = 3): Promise<number> {
    const base = await Promise.resolve(value);
    return base * scale;
}

async function destructured({ a, b }: { a: number; b: number }): Promise<number> {
    return (await Promise.resolve(a)) - b;
}

async function main(): Promise<void> {
    console.log(await countArgs(1, 2, 3, 4));
    console.log(await withDefault(4));
    console.log(await withDefault(4, 10));
    console.log(await destructured({ a: 10, b: 4 }));
}

main();

export {};
