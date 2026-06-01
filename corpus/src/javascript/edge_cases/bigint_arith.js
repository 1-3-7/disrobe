const big = 2n ** 128n;
const literal = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFn;
const product = big * 3n;
const fromMixed = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
const shifted = big >> 64n;
const masked = literal & 0xFFFF_FFFF_FFFF_FFFFn;

console.log({
    big: big.toString(),
    literal: literal.toString(16),
    product: product.toString(),
    fromMixed: fromMixed.toString(),
    shifted: shifted.toString(),
    masked: masked.toString(16),
});
