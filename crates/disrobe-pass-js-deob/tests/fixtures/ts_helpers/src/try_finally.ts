const log: string[] = [];

function settle(ok: boolean, value: string): Promise<string> {
    return ok ? Promise.resolve(value) : Promise.reject(new Error(value));
}

async function guarded(ok: boolean): Promise<string> {
    log.push("enter " + ok);
    try {
        const value = await settle(ok, "v" + ok);
        log.push("got " + value);
        return value;
    } catch (error) {
        log.push("caught " + (error as Error).message);
        return "fallback";
    } finally {
        log.push("finally " + ok);
    }
}

async function cleanup(): Promise<number> {
    let count = 0;
    try {
        count += await Promise.resolve(1);
        try {
            count += await Promise.resolve(10);
            await settle(false, "inner");
        } finally {
            count += 100;
            log.push("inner finally " + count);
        }
    } catch (error) {
        log.push("outer caught " + (error as Error).message);
        count += await Promise.resolve(1000);
    }
    return count;
}

async function finallyAwait(): Promise<string> {
    try {
        return await settle(true, "body");
    } finally {
        await Promise.resolve(0);
        log.push("awaited in finally");
    }
}

async function rethrow(): Promise<void> {
    try {
        await settle(false, "boom");
    } catch (error) {
        log.push("rethrowing " + (error as Error).message);
        throw new Error("again " + (error as Error).message);
    }
}

async function main(): Promise<void> {
    console.log(await guarded(true));
    console.log(await guarded(false));
    console.log(await cleanup());
    console.log(await finallyAwait());
    try {
        await rethrow();
    } catch (error) {
        console.log("main caught " + (error as Error).message);
    }
    console.log(log.join(";"));
}

main();

export {};
