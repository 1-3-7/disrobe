export function asConst<const T>(value: T): T {
    return value;
}

export function pickKeys<const K extends ReadonlyArray<string>>(keys: K): K {
    return keys;
}

const tuple = asConst([1, "two", true]);
const keys = pickKeys(["alpha", "beta", "gamma"]);

export type TupleType = typeof tuple;
export type Keys = typeof keys[number];
export const tupleHead = tuple[0];
