export function format(value: number): string;
export function format(value: string): string;
export function format(value: Date): string;
export function format(value: ReadonlyArray<number>): string;
export function format(value: number | string | Date | ReadonlyArray<number>): string {
    if (typeof value === "number") return value.toFixed(2);
    if (typeof value === "string") return `"${value}"`;
    if (value instanceof Date) return value.toISOString();
    return `[${value.join(",")}]`;
}

interface Builder<T> {
    add(value: T): Builder<T>;
    add(values: ReadonlyArray<T>): Builder<T>;
    build(): ReadonlyArray<T>;
}

export function makeBuilder<T>(): Builder<T> {
    const items: T[] = [];
    return {
        add(value: T | ReadonlyArray<T>): Builder<T> {
            if (Array.isArray(value)) items.push(...value);
            else items.push(value as T);
            return this;
        },
        build(): ReadonlyArray<T> {
            return items.slice();
        },
    };
}

export const samples = [format(3.14159), format("hi"), format(new Date(0)), format([1, 2, 3])];
