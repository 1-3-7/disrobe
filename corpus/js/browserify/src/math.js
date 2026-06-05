const add = (a, b) => a + b;
const mul = (a, b) => a * b;
const sum = (xs) => xs.reduce(add, 0);
const factorial = (n) => (n <= 1 ? 1 : mul(n, factorial(n - 1)));
module.exports = { add, mul, sum, factorial };
