const buffer = new ArrayBuffer(32);
const u32 = new Uint32Array(buffer);
const f64 = new Float64Array(buffer);
const dv = new DataView(buffer);

u32[0] = 0xDEADBEEF;
u32[1] = 0xCAFEBABE;
dv.setBigInt64(16, 0x0123_4567_89AB_CDEFn, true);

const reinterpreted = f64[0];
const tail = dv.getBigInt64(16, true);
const sliced = new Uint8Array(buffer.slice(0, 8));

console.log({
    u32: [u32[0].toString(16), u32[1].toString(16)],
    reinterpretedBits: reinterpreted,
    tail: tail.toString(16),
    sliced: Array.from(sliced).map((b) => b.toString(16).padStart(2, "0")),
});
