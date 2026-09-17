declare global {
    interface Array<T> {
        compact(): NonNullable<T>[];
        firstOrThrow(): T;
    }
    interface String {
        ensurePrefix(prefix: string): string;
    }
}

Array.prototype.compact = function compact<T>(this: T[]): NonNullable<T>[] {
    return this.filter((x): x is NonNullable<T> => x !== null && x !== undefined);
};

Array.prototype.firstOrThrow = function firstOrThrow<T>(this: T[]): T {
    if (this.length === 0) throw new Error("empty");
    return this[0]!;
};

String.prototype.ensurePrefix = function ensurePrefix(this: string, prefix: string): string {
    return this.startsWith(prefix) ? this : `${prefix}${this}`;
};

export const samples = {
    compacted: [1, null, 2, undefined, 3].compact(),
    first: ["a", "b"].firstOrThrow(),
    prefixed: "world".ensurePrefix("hello-"),
};
