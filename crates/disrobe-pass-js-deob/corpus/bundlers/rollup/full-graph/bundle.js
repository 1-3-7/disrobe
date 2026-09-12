/*
 * Bundled with Rollup
 */
Object.defineProperty(exports, '__esModule', { value: true });

export const VERSION = "1.0.0";

export function greet(name) {
  return "hello " + name;
}

export class Widget {
  constructor(label) {
    this.label = label;
  }
  render() {
    return "<w>" + this.label + "</w>";
  }
}
//# sourceMappingURL=lib.js.map
