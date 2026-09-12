function rethrowWithFinally() {
    try {
        try {
            throw new Error("inner");
        } catch (err) {
            throw new Error(`wrapped: ${err.message}`);
        } finally {
            return "finally-wins";
        }
    } catch (err) {
        return `outer-caught: ${err.message}`;
    }
}

function asyncFinally() {
    return Promise.resolve()
        .then(() => { throw new Error("async-inner"); })
        .catch((err) => err.message)
        .finally(() => "finally-ignored");
}

asyncFinally().then((msg) => console.log({ sync: rethrowWithFinally(), async: msg }));
