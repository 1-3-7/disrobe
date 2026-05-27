export type Push<T extends ReadonlyArray<unknown>, U> = readonly [...T, U];
export type Unshift<T extends ReadonlyArray<unknown>, U> = readonly [U, ...T];
export type Concat<A extends ReadonlyArray<unknown>, B extends ReadonlyArray<unknown>> = readonly [...A, ...B];
export type Drop1<T extends ReadonlyArray<unknown>> = T extends readonly [unknown, ...infer Rest] ? Rest : never;

declare const pushed: Push<readonly [1, 2, 3], 4>;
declare const concatenated: Concat<readonly ["a"], readonly ["b", "c"]>;
declare const dropped: Drop1<readonly [1, 2, 3]>;

export function curry<A extends unknown[], R>(fn: (...args: A) => R) {
    return function inner<P extends Partial<A>>(...partial: P) {
        return (...rest: A) => fn(...rest);
    };
}

export const samples = { pushed, concatenated, dropped };
