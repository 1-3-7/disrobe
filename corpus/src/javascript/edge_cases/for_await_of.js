async function* source() {
    for (let i = 1; i <= 5; i++) {
        await Promise.resolve();
        yield i;
    }
}

async function consume() {
    const collected = [];
    for await (const value of source()) {
        if (value > 3) break;
        collected.push(value * value);
    }
    return collected;
}

consume().then((out) => console.log(out));
