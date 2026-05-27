function sloppy(scope) {
    with (scope) {
        return `${greeting} ${name}!`;
    }
}

const out = sloppy({ greeting: "hello", name: "world" });

const compiled = new Function("ctx", "with (ctx) { return greeting + ' ' + name; }");
const out2 = compiled({ greeting: "hi", name: "there" });

console.log({ out, out2 });
