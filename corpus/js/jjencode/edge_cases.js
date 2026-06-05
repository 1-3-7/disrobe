"use strict";


var legacyVar = 1;
let blockLet = 2;
const blockConst = 3;
{
  let blockLet = 22;
  const blockConst = 33;
  var legacyVar = 11;
}


const identity = (x) => x;
const addOne = (x) => x + 1;
const addAll = (...nums) => nums.reduce((a, b) => a + b, 0);
const greeter = (name = "world", greeting = "hello") => `${greeting} ${name}`;
const merged = { ...{ a: 1 }, ...{ b: 2 } };
const concat = [1, ...[2, 3], 4];


const [first, second, ...rest] = [1, 2, 3, 4, 5];
const { x: aliasedX = 10, y: aliasedY = 20 } = { x: 7 };
const {
  nested: { deep: { value: deepValue = 99 } = {} } = {},
} = { nested: { deep: { value: 1 } } };
function destructured({ id, name = "anon" } = {}) {
  return `${id}:${name}`;
}


class Animal {
  static #count = 0;
  #name;
  #age = 0;
  legs;

  constructor(name, legs) {
    this.#name = name;
    this.legs = legs;
    Animal.#count += 1;
  }

  get name() {
    return this.#name;
  }

  set name(v) {
    this.#name = String(v);
  }

  static get count() {
    return Animal.#count;
  }

  #internal() {
    return `${this.#name}@${this.#age}`;
  }

  describe() {
    return `${this.#internal()} has ${this.legs} legs`;
  }

  static create(name, legs) {
    return new Animal(name, legs);
  }
}

class Dog extends Animal {
  constructor(name) {
    super(name, 4);
  }
  bark() {
    return `${this.name} says woof`;
  }
}


async function asyncDouble(n) {
  return n * 2;
}

async function* asyncRange(start, end) {
  for (let i = start; i < end; i++) {
    yield await asyncDouble(i);
  }
}

function* fibonacci(n) {
  let [a, b] = [0, 1];
  for (let i = 0; i < n; i++) {
    yield a;
    [a, b] = [b, a + b];
  }
}

async function consumeAsyncIter() {
  const collected = [];
  for await (const v of asyncRange(0, 5)) {
    collected.push(v);
  }
  return collected;
}


async function combinators() {
  const resolved = Promise.resolve(1);
  const all = await Promise.all([resolved, Promise.resolve(2)]);
  const settled = await Promise.allSettled([
    resolved,
    Promise.reject(new Error("nope")),
  ]);
  const raced = await Promise.race([
    new Promise((r) => setTimeout(() => r("a"), 10)),
    new Promise((r) => setTimeout(() => r("b"), 20)),
  ]);
  const anyResult = await Promise.any([
    Promise.reject("x"),
    Promise.resolve("y"),
  ]);
  return { all, settled, raced, anyResult };
}


function tag(strings, ...values) {
  return strings
    .map((s, i) => `${s}<${values[i] ?? ""}>`)
    .join("");
}

const tagged = tag`a${1}b${2}c${3}`;
const multiline = `line1
line2
line3 with ${1 + 1}`;


const optChain = ({ a }) => a?.b?.c?.d ?? "fallback";
const nullish = null ?? "default";
let logA = null;
logA ??= "set";
let logB = 0;
logB ||= 5;
let logC = 1;
logC &&= 10;


const big = 9007199254740993n + 1n;
const bigPow = 2n ** 64n;
const sym = Symbol("disrobe");
const symFor = Symbol.for("shared");
class Iterable {
  *[Symbol.iterator]() {
    yield 1;
    yield 2;
    yield 3;
  }
  get [Symbol.toStringTag]() {
    return "Iterable";
  }
}


const wm = new WeakMap();
const ws = new WeakSet();
const wrTarget = { id: 1 };
const wr = new WeakRef(wrTarget);
const fr = new FinalizationRegistry((heldValue) => {
  void heldValue;
});

const proxy = new Proxy(
  { existing: 1 },
  {
    get(target, prop, receiver) {
      if (prop in target) return Reflect.get(target, prop, receiver);
      return `synth:${String(prop)}`;
    },
    set(target, prop, value, receiver) {
      return Reflect.set(target, prop, value, receiver);
    },
    has(target, prop) {
      return Reflect.has(target, prop) || prop === "synthetic";
    },
  },
);


const i8 = new Int8Array(4);
const u8 = new Uint8Array(4);
const u8c = new Uint8ClampedArray(4);
const i16 = new Int16Array(4);
const u16 = new Uint16Array(4);
const i32 = new Int32Array(4);
const u32 = new Uint32Array(4);
const f32 = new Float32Array(4);
const f64 = new Float64Array(4);
const bi64 = new BigInt64Array(2);
const bu64 = new BigUint64Array(2);
const ab = new ArrayBuffer(16);
const dv = new DataView(ab);
dv.setUint32(0, 0xdeadbeef);


const m = new Map([
  ["a", 1],
  ["b", 2],
]);
const s = new Set([1, 2, 3, 2]);
for (const [k, v] of m) {
  void [k, v];
}
for (const item of s) {
  void item;
}
const fromIter = Array.from(s);
const spread = [...s];


const arr = [10, 20, 30];
const atResult = arr.at(-1);
const flat = [1, [2, [3, [4]]]].flat(Infinity);
const flatMapped = [1, 2, 3].flatMap((n) => [n, n * 2]);
const includes = [NaN].includes(NaN);
const findLast = arr.findLast((n) => n > 10);
const findLastIndex = arr.findLastIndex((n) => n > 10);
const grouped = Object.groupBy
  ? Object.groupBy([1, 2, 3, 4], (n) => (n % 2 === 0 ? "even" : "odd"))
  : { even: [], odd: [] };


const hasOwn = Object.hasOwn({ a: 1 }, "a");
const cloned = typeof structuredClone === "function"
  ? structuredClone({ nested: { value: 1 } })
  : { nested: { value: 1 } };
const entriesObj = Object.fromEntries([
  ["one", 1],
  ["two", 2],
]);


const dateRe = /^(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})$/;
const dateMatch = "2026-05-25".match(dateRe);
const behindRe = /(?<=USD\s)\d+/;
const aheadRe = /\d+(?=\sUSD)/;
const stickyRe = /\d+/y;
const unicodeRe = /\p{Letter}+/gu;
const dotAllRe = /a.b/s;


const padded = "1".padStart(4, "0") + "x".padEnd(3, "-");
const trimmed = "  abc  ".trimStart().trimEnd();
const replaceAll = "a-b-c".replaceAll("-", "_");
const numericSep = 1_000_000;
const hexBig = 0xff_ff_ffn;
const expForm = 1e3;
const binLit = 0b1010_0101;
const octLit = 0o755;


const u1 = "é";
const u2 = "\u{1F600}";
const u3 = "\xff";
const u4 = "\\";
const u5 = "\n\r\t\v\f\b\0";


const url = new URL("https://example.com/path?q=1#frag");
const params = new URLSearchParams("a=1&b=2");
const ac = new AbortController();
const fetchAvailable = typeof fetch === "function";
function abortableFetch(target) {
  if (!fetchAvailable) return Promise.resolve(null);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 0);
  return fetch(target, { signal: controller.signal }).catch(() => null);
}


const protoA = { kind: "A" };
const protoB = Object.create(protoA);
protoB.extra = "B";
const inst = Object.create(protoB);
const ownNames = Object.getOwnPropertyNames(protoB);
const proto = Object.getPrototypeOf(inst);
Object.setPrototypeOf(inst, protoA);


const jsxLike = (props) => {
  return {
    type: "div",
    props: {
      className: props.className ?? "",
      children: props.children,
    },
  };
};


const moduleResult = (function () {
  const secret = 42;
  return {
    reveal() {
      return secret;
    },
  };
})();

const arrowIife = (() => 7)();


function risky(input) {
  try {
    if (typeof input !== "number") throw new TypeError("need number");
    return input * 2;
  } catch {
    return -1;
  } finally {
    void "cleanup";
  }
}


outer: for (let i = 0; i < 3; i++) {
  inner: for (let j = 0; j < 3; j++) {
    if (i === 1 && j === 1) continue outer;
    if (i === 2 && j === 2) break outer;
    void [i, j];
  }
}


function classify(n) {
  switch (true) {
    case n < 0:
      return "neg";
    case n === 0:
      return "zero";
    case n > 0 && n < 10:
    case n === 10:
      return "small";
    default:
      return "big";
  }
}


const dynKey = "computed";
const computedObj = {
  [dynKey]: 1,
  [`${dynKey}_2`]: 2,
  shorthand: dynKey,
  method() {
    return this[dynKey];
  },
  async asyncMethod() {
    return this[dynKey];
  },
  *gen() {
    yield this[dynKey];
  },
};


function factorial(n, acc = 1) {
  if (n <= 1) return acc;
  return factorial(n - 1, acc * n);
}


function chained() {
  try {
    throw new Error("root");
  } catch (root) {
    throw new Error("wrapper", { cause: root });
  }
}

function aggregated() {
  return new AggregateError(
    [new Error("a"), new Error("b")],
    "two failures",
  );
}


async function loadDynamic(name) {
  if (false) {
    return await import(name);
  }
  return null;
}


function* outer() {
  yield 1;
  yield* [2, 3];
  yield* fibonacci(3);
  return "done";
}


const forInKeys = [];
for (const k in { a: 1, b: 2 }) forInKeys.push(k);
const forOfValues = [];
for (const v of [10, 20]) forOfValues.push(v);


const max = Math.max(...[1, 5, 3, 4]);
const date = new Date(...[2026, 4, 25]);


function rawTag(strings) {
  return strings.raw.join("|");
}
const rawResult = rawTag`a\nb\tc`;


const sealed = Object.seal({ a: 1 });
const frozen = Object.freeze({ b: 2 });
const desc = Object.getOwnPropertyDescriptor(frozen, "b");
const descriptorTarget = { b: 2 };
Object.defineProperty(descriptorTarget, "c", {
  value: 3,
  writable: false,
  configurable: false,
  enumerable: false,
});


class Counter {
  count = 0;
  inc = async () => {
    this.count += 1;
    return this.count;
  };
  decBound = function () {
    this.count -= 1;
    return this.count;
  }.bind(this);
}


const SENTINEL = Object.freeze({
  ok: true,
  version: "1.0.0",
  symbols: { iter: Symbol.iterator, asyncIter: Symbol.asyncIterator },
});


const exportsGate = {
  Animal,
  Dog,
  Counter,
  Iterable,
  greeter,
  destructured,
  combinators,
  consumeAsyncIter,
  fibonacci,
  factorial,
  classify,
  risky,
  chained,
  aggregated,
  loadDynamic,
  tagged,
  multiline,
  rawResult,
  computedObj,
  optChain,
  nullish,
  jsxLike,
  proxy,
  moduleResult,
  arrowIife,
  SENTINEL,
};


console.log(
  JSON.stringify({
    version: SENTINEL.version,
    keys: Object.keys(exportsGate).length,
    big: String(big),
    cloned: cloned.nested.value,
    flat: flat.length,
    factorial: factorial(5),
  }),
);
