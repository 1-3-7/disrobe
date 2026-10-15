let instance = null;
const env = {
  k0: (a, b) => a ^ b,
  "k1": function (x, y) { return (x + y) | 0; },
  k2: (p, q) => (q & p),
  k3: (a, b) => Math.imul(a, b),
  k4: eval("(l, r) => l ^ r"),
  k5: new Function("v", "s", "return v >>> s"),
  k6: (a, b) => instance.exports.eval0(a, b),
  k7: (a, b) => a * b,
};

async function load(bytes) {
  const result = await WebAssembly.instantiate(bytes, { env });
  instance = result.instance;
  return instance.exports;
}

module.exports = { load };
