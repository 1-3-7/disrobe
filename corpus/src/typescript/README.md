# TypeScript playground

Hand-authored TS sources fed through `tsc` first, then `disrobe-pass-js-deob` on the emitted JS. TS5 stage-3 decorators + generics + abstract classes exercise the parts of obfuscator output that survive `tsc` lowering.

| file | target | how to feed disrobe |
|------|--------|---------------------|
| `decorators-target.ts` | TS5 stage-3 method decorator + generic `Calculator<T>` (decorator metadata + class fields survive minification) | `tsc decorators-target.ts --strict --target ES2022 && disrobe js deob decorators-target.js` |
| `class-target.ts` | abstract `Repository<T>` + extension + private/protected fields + index signature (private becomes underscore in JS output) | `tsc class-target.ts --strict --target ES2022 && disrobe js deob class-target.js` |

After `tsc`, optionally pipe through `javascript-obfuscator` / `js-confuser` to stack JS-level obfuscation on top of TS lowering before running disrobe.
