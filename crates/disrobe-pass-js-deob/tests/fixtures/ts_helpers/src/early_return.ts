const cache: { [key: string]: number } = {};

function fetchValue(key: string): Promise<number> {
    return Promise.resolve(key.length * 7);
}

async function lookup(key: string): Promise<number> {
    if (key in cache) {
        return cache[key];
    }
    if (key === "") {
        return -1;
    }
    const value = await fetchValue(key);
    if (value > 20) {
        cache[key] = value;
        return value;
    }
    const doubled = await fetchValue(key + key);
    return doubled;
}

async function classify(value: number): Promise<string> {
    if (value < 0) {
        return "negative";
    } else if (value === 0) {
        await Promise.resolve();
        return "zero";
    }
    const scaled = await Promise.resolve(value * 10);
    return scaled > 50 ? "large" : "small";
}

async function nothing(flag: boolean): Promise<void> {
    if (flag) {
        return;
    }
    await Promise.resolve();
    console.log("nothing continued");
}

async function main(): Promise<void> {
    console.log(await lookup("abc"));
    console.log(await lookup("abcd"));
    console.log(await lookup("abcd"));
    console.log(await lookup(""));
    console.log(await lookup("a"));
    console.log(await classify(-3));
    console.log(await classify(0));
    console.log(await classify(2));
    console.log(await classify(9));
    await nothing(true);
    await nothing(false);
}

main();

export {};
