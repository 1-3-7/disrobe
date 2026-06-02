class TrackedResource implements Disposable {
    static disposed: string[] = [];
    constructor(public readonly label: string) {}
    use(): string {
        return `using ${this.label}`;
    }
    [Symbol.dispose](): void {
        TrackedResource.disposed.push(this.label);
    }
}

class AsyncResource implements AsyncDisposable {
    static disposed: string[] = [];
    constructor(public readonly label: string) {}
    async [Symbol.asyncDispose](): Promise<void> {
        await Promise.resolve();
        AsyncResource.disposed.push(this.label);
    }
}

export function workSync(): string {
    using r1 = new TrackedResource("first");
    using r2 = new TrackedResource("second");
    return `${r1.use()}|${r2.use()}`;
}

export async function workAsync(): Promise<string> {
    await using r = new AsyncResource("async-first");
    return `async-using ${r.label}`;
}

export const sample = { workSync, workAsync };
