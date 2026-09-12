export type ArrayOrSelf<T> = T extends unknown ? T[] | T : never;
export type Boxed<T> = T extends infer U ? { value: U } : never;
export type NonNullable2<T> = T extends null | undefined ? never : T;
export type ElementOf<T> = T extends ReadonlyArray<infer U> ? U : never;

declare const sample1: ArrayOrSelf<string | number>;
declare const sample2: ElementOf<readonly [1, "two", true]>;
declare const sample3: NonNullable2<string | null | undefined>;
declare const boxed: Boxed<{ a: 1 }>;

export const tagged = { sample1, sample2, sample3, boxed };
