export type ReturnTypeOf<F> = F extends (...args: any[]) => infer R ? R : never;
export type FirstParam<F> = F extends (first: infer A, ...rest: any[]) => any ? A : never;
export type PromiseValue<T> = T extends Promise<infer V> ? V : T;
export type DeepUnpromise<T> = T extends Promise<infer U> ? DeepUnpromise<U> : T;
export type HeadAndRest<T> = T extends readonly [infer H, ...infer R] ? { head: H; rest: R } : never;

declare const ret: ReturnTypeOf<() => number>;
declare const first: FirstParam<(a: string, b: boolean) => void>;
declare const unwrapped: PromiseValue<Promise<{ ok: true }>>;
declare const deep: DeepUnpromise<Promise<Promise<Promise<string>>>>;
declare const split: HeadAndRest<readonly [1, "x", true]>;

export const proof = { ret, first, unwrapped, deep, split };
