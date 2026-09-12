export const sentinel: unique symbol = Symbol("sentinel");
export type Sentinel = typeof sentinel;

declare const refKey: unique symbol;
export interface RefHolder<T> {
    readonly [refKey]: T;
}

export function makeRef<T>(value: T): RefHolder<T> {
    return { [refKey]: value } as RefHolder<T>;
}

export const flag: Sentinel = sentinel;
export const wrapped = makeRef({ hello: "world" });
