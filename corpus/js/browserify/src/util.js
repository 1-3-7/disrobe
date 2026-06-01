const greet = (name) => `hello ${name}`;
const repeat = (s, n) => Array(n).fill(s).join(" ");
class Counter {
  constructor() {
    this._count = 0;
  }
  inc() {
    this._count += 1;
    return this._count;
  }
  get value() {
    return this._count;
  }
}
module.exports = { greet, repeat, Counter };
