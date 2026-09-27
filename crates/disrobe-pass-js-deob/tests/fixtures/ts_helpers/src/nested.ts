function double(value: number): Promise<number> {
    return Promise.resolve(value * 2);
}

function join(left: number, right: number): Promise<string> {
    return Promise.resolve(left + ":" + right);
}

async function nestedCalls(seed: number): Promise<string> {
    return await join(await double(seed), await double(await double(seed)));
}

async function inExpressions(seed: number): Promise<number> {
    const sum = (await double(seed)) + (await double(seed + 1)) * 2;
    const pick = seed > 2 ? await double(sum) : await double(-sum);
    const flags = [await double(1), await double(2)];
    return pick + flags[0] + flags[1];
}

async function inner(label: string): Promise<string> {
    const part = await Promise.resolve(label);
    return "<" + part + ">";
}

async function outer(): Promise<string> {
    const parts: string[] = [];
    parts.push(await inner("a"));
    parts.push(await inner(await inner("b")));
    const wrapped = async (value: string): Promise<string> => "[" + (await inner(value)) + "]";
    parts.push(await wrapped("c"));
    return parts.join("");
}

async function main(): Promise<void> {
    console.log(await nestedCalls(3));
    console.log(await inExpressions(1));
    console.log(await inExpressions(5));
    console.log(await outer());
}

main();

export {};
