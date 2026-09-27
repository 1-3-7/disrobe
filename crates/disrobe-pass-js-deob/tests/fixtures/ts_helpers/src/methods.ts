class Counter {
    private value: number;

    constructor(start: number) {
        this.value = start;
    }

    async increment(step: number): Promise<number> {
        this.value += await Promise.resolve(step);
        return this.value;
    }

    async runMany(steps: number[]): Promise<number[]> {
        const results: number[] = [];
        for (const step of steps) {
            results.push(await this.increment(step));
        }
        return results;
    }

    delayedRead(): Promise<string> {
        const read = async (): Promise<string> => {
            await Promise.resolve();
            return "value=" + this.value;
        };
        return read();
    }

    static async create(start: number): Promise<Counter> {
        const initial = await Promise.resolve(start * 2);
        return new Counter(initial);
    }
}

const helpers = {
    base: 5,
    async scaled(factor: number): Promise<number> {
        return this.base * (await Promise.resolve(factor));
    },
};

async function main(): Promise<void> {
    const counter = await Counter.create(3);
    console.log(await counter.increment(4));
    console.log((await counter.runMany([1, 2, 3])).join(","));
    console.log(await counter.delayedRead());
    console.log(await helpers.scaled(6));
}

main();

export {};
