const million = 1_000_000;
const hex = 0xFF_EC_DE_5E;
const binary = 0b1010_0001_1000_0101;
const octal = 0o755_644;
const decimalFraction = 0.000_001;
const huge = 1_234_567_890_123_456n;
const exponent = 1.5e2_0;

console.log({ million, hex, binary, octal, decimalFraction, huge: huge.toString(), exponent });
