"use strict";

function evalScope() {
    eval("var leaked = 'inside';");
    return typeof leaked === "undefined" ? "isolated" : "escaped";
}

const indirectAlias = eval;
const indirectResult = (() => {
    indirectAlias("var globalLeak = 99;");
    return globalThis.globalLeak ?? "missing";
})();

console.log({ direct: evalScope(), indirect: indirectResult });
