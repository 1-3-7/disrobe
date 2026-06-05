declare var legacyVar: number;
declare let blockLet: number;
declare const blockConst = 3;
declare const identity: (x: any) => any;
declare const addOne: (x: any) => any;
declare const addAll: (...nums: any[]) => any;
declare const greeter: (name?: string, greeting?: string) => string;
declare const merged: {
    b: number;
    a: number;
};
declare const concat: number[];
declare const first: number, second: number, rest: [number, number, number];
declare const aliasedX: number, aliasedY: number;
declare const deepValue: number;
declare function destructured({ id, name }?: {
    name?: string;
}): string;
declare class Animal {
    #private;
    legs: any;
    constructor(name: any, legs: any);
    get name(): any;
    set name(v: any);
    static get count(): number;
    describe(): string;
    static create(name: any, legs: any): Animal;
}
declare class Dog extends Animal {
    constructor(name: any);
    bark(): string;
}
declare function asyncDouble(n: any): Promise<number>;
declare function asyncRange(start: any, end: any): AsyncGenerator<number, void, unknown>;
declare function fibonacci(n: any): Generator<number, void, unknown>;
declare function consumeAsyncIter(): Promise<any[]>;
declare function combinators(): Promise<{
    all: [number, number];
    settled: [PromiseSettledResult<number>, PromiseSettledResult<never>];
    raced: unknown;
    anyResult: string;
}>;
declare function tag(strings: any, ...values: any[]): any;
declare const tagged: any;
declare const multiline = "line1\nline2\nline3 with 2";
declare const optChain: ({ a }: {
    a: any;
}) => any;
declare const nullish = "default";
declare let logA: any;
declare let logB: number;
declare let logC: number;
declare const big: bigint;
declare const bigPow: bigint;
declare const sym: unique symbol;
declare const symFor: unique symbol;
declare class Iterable {
    get [Symbol.toStringTag](): string;
}
declare const wm: WeakMap<object, any>;
declare const ws: WeakSet<object>;
declare const wrTarget: {
    id: number;
};
declare const wr: WeakRef<{
    id: number;
}>;
declare const fr: FinalizationRegistry<unknown>;
declare const proxy: {
    existing: number;
};
declare const i8: Int8Array<ArrayBuffer>;
declare const u8: Uint8Array<ArrayBuffer>;
declare const u8c: Uint8ClampedArray<ArrayBuffer>;
declare const i16: Int16Array<ArrayBuffer>;
declare const u16: Uint16Array<ArrayBuffer>;
declare const i32: Int32Array<ArrayBuffer>;
declare const u32: Uint32Array<ArrayBuffer>;
declare const f32: Float32Array<ArrayBuffer>;
declare const f64: Float64Array<ArrayBuffer>;
declare const bi64: BigInt64Array<ArrayBuffer>;
declare const bu64: BigUint64Array<ArrayBuffer>;
declare const ab: ArrayBuffer;
declare const dv: DataView<ArrayBuffer>;
declare const m: Map<string, number>;
declare const s: Set<number>;
declare const fromIter: number[];
declare const spread: number[];
declare const arr: number[];
declare const atResult: number;
declare const flat: FlatArray<number | (number | (number | number[])[])[], 0 | 2 | 1 | 3 | 4 | 8 | 16 | 5 | 6 | 9 | 10 | 7 | 12 | 11 | 14 | 13 | 15 | 17 | 18 | 19 | 20 | -1>[];
declare const flatMapped: number[];
declare const includes: boolean;
declare const findLast: any;
declare const findLastIndex: any;
declare const grouped: any;
declare const hasOwn: boolean;
declare const cloned: {
    nested: {
        value: number;
    };
};
declare const entriesObj: {
    [k: string]: any;
};
declare const dateRe: RegExp;
declare const dateMatch: RegExpMatchArray;
declare const behindRe: RegExp;
declare const aheadRe: RegExp;
declare const stickyRe: RegExp;
declare const unicodeRe: RegExp;
declare const dotAllRe: RegExp;
declare const padded: string;
declare const trimmed: string;
declare const replaceAll: string;
declare const numericSep = 1000000;
declare const hexBig = 16777215n;
declare const expForm = 1000;
declare const binLit = 165;
declare const octLit = 493;
declare const u1 = "\u00E9";
declare const u2 = "\uD83D\uDE00";
declare const u3 = "\u00FF";
declare const u4 = "\\";
declare const u5 = "\n\r\t\v\f\b\0";
declare const url: URL;
declare const params: URLSearchParams;
declare const ac: AbortController;
declare const fetchAvailable: boolean;
declare function abortableFetch(target: any): Promise<any>;
declare const protoA: {
    kind: string;
};
declare const protoB: any;
declare const inst: any;
declare const ownNames: string[];
declare const proto: any;
declare const jsxLike: (props: any) => {
    type: string;
    props: {
        className: any;
        children: any;
    };
};
declare const moduleResult: {
    reveal(): number;
};
declare const arrowIife: number;
declare function risky(input: any): number;
declare function classify(n: any): "zero" | "neg" | "small" | "big";
declare const dynKey = "computed";
declare const computedObj: {
    computed: number;
    computed_2: number;
    shorthand: string;
    method(): any;
    asyncMethod(): Promise<any>;
    gen(): Generator<any, void, unknown>;
};
declare function factorial(n: any, acc?: number): number;
declare function chained(): void;
declare function aggregated(): AggregateError;
declare function loadDynamic(name: any): Promise<any>;
declare function outer(): Generator<number, string, unknown>;
declare const forInKeys: any[];
declare const forOfValues: any[];
declare const max: number;
declare const date: Date;
declare function rawTag(strings: any): any;
declare const rawResult: any;
declare const sealed: {
    a: number;
};
declare const frozen: Readonly<{
    b: 2;
}>;
declare const desc: PropertyDescriptor;
declare const descriptorTarget: {
    b: number;
};
declare class Counter {
    count: number;
    inc: () => Promise<number>;
    decBound: any;
}
declare const SENTINEL: Readonly<{
    ok: true;
    version: "1.0.0";
    symbols: {
        iter: symbol;
        asyncIter: symbol;
    };
}>;
declare const exportsGate: {
    Animal: typeof Animal;
    Dog: typeof Dog;
    Counter: typeof Counter;
    Iterable: typeof Iterable;
    greeter: (name?: string, greeting?: string) => string;
    destructured: typeof destructured;
    combinators: typeof combinators;
    consumeAsyncIter: typeof consumeAsyncIter;
    fibonacci: typeof fibonacci;
    factorial: typeof factorial;
    classify: typeof classify;
    risky: typeof risky;
    chained: typeof chained;
    aggregated: typeof aggregated;
    loadDynamic: typeof loadDynamic;
    tagged: any;
    multiline: string;
    rawResult: any;
    computedObj: {
        computed: number;
        computed_2: number;
        shorthand: string;
        method(): any;
        asyncMethod(): Promise<any>;
        gen(): Generator<any, void, unknown>;
    };
    optChain: ({ a }: {
        a: any;
    }) => any;
    nullish: string;
    jsxLike: (props: any) => {
        type: string;
        props: {
            className: any;
            children: any;
        };
    };
    proxy: {
        existing: number;
    };
    moduleResult: {
        reveal(): number;
    };
    arrowIife: number;
    SENTINEL: Readonly<{
        ok: true;
        version: "1.0.0";
        symbols: {
            iter: symbol;
            asyncIter: symbol;
        };
    }>;
};
