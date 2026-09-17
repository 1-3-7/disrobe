export const add = (a, b) => a + b;
export const mul = (a, b) => a * b;
export const sum = (xs) => xs.reduce(add, 0);
export const factorial = (n) => (n <= 1 ? 1 : mul(n, factorial(n - 1)));
