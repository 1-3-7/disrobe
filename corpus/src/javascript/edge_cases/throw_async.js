async function failer(kind) {
    if (kind === "sync") throw new Error("sync-throw");
    if (kind === "async") return Promise.reject(new Error("async-reject"));
    if (kind === "delayed") return new Promise((_, r) => setTimeout(() => r(new TypeError("delayed")), 1));
    return "ok";
}

async function harness() {
    const out = {};
    for (const kind of ["sync", "async", "delayed", "ok"]) {
        try {
            out[kind] = await failer(kind);
        } catch (e) {
            out[kind] = `caught:${e.name}:${e.message}`;
        }
    }
    return out;
}

harness().then((r) => console.log(r));
