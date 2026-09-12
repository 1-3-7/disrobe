const log = [];
const target = { a: 1, b: 2 };
const handler = {
    get(t, k, r) { log.push(["get", k]); return Reflect.get(t, k, r); },
    set(t, k, v, r) { log.push(["set", k, v]); return Reflect.set(t, k, v, r); },
    has(t, k) { log.push(["has", k]); return Reflect.has(t, k); },
    deleteProperty(t, k) { log.push(["delete", k]); return Reflect.deleteProperty(t, k); },
    ownKeys(t) { log.push(["ownKeys"]); return Reflect.ownKeys(t); },
    getOwnPropertyDescriptor(t, k) { log.push(["gopd", k]); return Reflect.getOwnPropertyDescriptor(t, k); },
    defineProperty(t, k, d) { log.push(["defineProperty", k]); return Reflect.defineProperty(t, k, d); },
    getPrototypeOf(t) { log.push(["getPrototypeOf"]); return Reflect.getPrototypeOf(t); },
    setPrototypeOf(t, p) { log.push(["setPrototypeOf"]); return Reflect.setPrototypeOf(t, p); },
    isExtensible(t) { log.push(["isExtensible"]); return Reflect.isExtensible(t); },
    preventExtensions(t) { log.push(["preventExtensions"]); return Reflect.preventExtensions(t); },
    apply(t, thisArg, args) { log.push(["apply"]); return Reflect.apply(t, thisArg, args); },
    construct(t, args, nt) { log.push(["construct"]); return Reflect.construct(t, args, nt); },
};

const proxied = new Proxy(target, handler);
proxied.a;
proxied.c = 9;
"b" in proxied;
delete proxied.b;
Object.keys(proxied);
Object.getOwnPropertyDescriptor(proxied, "c");
Object.defineProperty(proxied, "d", { value: 4, enumerable: true });
Object.getPrototypeOf(proxied);
Object.isExtensible(proxied);

const fnProxy = new Proxy(function (x) { return x * 2; }, handler);
fnProxy(21);

console.log(log.map((e) => e.join(":")).join("|"));
