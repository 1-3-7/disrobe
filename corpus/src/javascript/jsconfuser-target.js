const SECRET_KEY = "disrobe-jsconfuser-target";
const ROUNDS = 16;

function rotateLeft(value, count) {
    const mask = 0xffffffff;
    const c = count & 31;
    return ((value << c) | (value >>> (32 - c))) & mask;
}

function mixState(state, key, round) {
    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    for (let i = 0; i < 4; i++) {
        const k = key.charCodeAt((round + i) % key.length);
        a = rotateLeft(a ^ b, 5) + k;
        b = rotateLeft(b ^ c, 7) + a;
        c = rotateLeft(c ^ d, 11) + b;
        d = rotateLeft(d ^ a, 13) + c;
    }
    return [a >>> 0, b >>> 0, c >>> 0, d >>> 0];
}

function deriveDigest(input) {
    let state = [0x12345678, 0x9abcdef0, 0xdeadbeef, 0xcafebabe];
    for (let r = 0; r < ROUNDS; r++) {
        state = mixState(state, input + SECRET_KEY, r);
    }
    return state.map((s) => s.toString(16).padStart(8, "0")).join("");
}

function verify(input, expected) {
    const got = deriveDigest(input);
    if (got !== expected) {
        throw new Error("digest mismatch for " + input);
    }
    return true;
}

function runAll() {
    const samples = ["alpha", "beta", "gamma", "delta"];
    const digests = samples.map((s) => [s, deriveDigest(s)]);
    digests.forEach(([s, d]) => console.log(s + " -> " + d));
    return digests;
}

runAll();
