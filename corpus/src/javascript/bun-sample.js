// @bun
var __require = function (path) { return Bun.resolveSync(path); };

__bun_register({
  "./a.ts": function (module, exports) {
    module.exports = function () { return 'alpha'; };
  },
  "./b.ts": function (module, exports) {
    module.exports = function () { return 'beta'; };
  }
});

export function main() {
  const a = __require('./a.ts');
  const b = __require('./b.ts');
  return a() + ',' + b();
}
