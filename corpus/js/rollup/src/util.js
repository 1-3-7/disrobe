export const greet = (name) => `hello ${name}`;
export const repeat = (s, n) => Array(n).fill(s).join(" ");
export class Counter {
  #count = 0;
  inc() {
    this.#count += 1;
    return this.#count;
  }
  get value() {
    return this.#count;
  }
}
