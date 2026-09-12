# TypeScript playground

TypeScript sources compile through `tsc` before `disrobe-pass-js-deob` processes the emitted JavaScript. Stage-3 decorators, generics, and abstract classes exercise the output of TypeScript lowering.

| file | target | how to feed disrobe |
|------|--------|---------------------|
| `decorators-target.ts` | TS5 stage-3 method decorator + generic `Calculator<T>` (decorator metadata + class fields survive minification) | `tsc decorators-target.ts --strict --target ES2022 && disrobe js deob decorators-target.js` |
| `class-target.ts` | abstract `Repository<T>` + extension + private/protected fields + index signature (private becomes underscore in JS output) | `tsc class-target.ts --strict --target ES2022 && disrobe js deob class-target.js` |

After `tsc`, optionally pipe through `javascript-obfuscator` / `js-confuser` to stack JS-level obfuscation on top of TS lowering before running disrobe.
