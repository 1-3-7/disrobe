(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
  typeof define === 'function' && define.amd ? define(['exports'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.MyLib = {}));
}(this, (function (exports) {
  Object.defineProperty(exports, '__esModule', { value: true });

  export const VERSION = '1.0.0';

  export function greet(name) {
    return 'hello ' + name;
  }

  export class Widget {
    constructor(label) { this.label = label; }
    render() { return '<div>' + this.label + '</div>'; }
  }
})));
