// @bun
var __require = function (p) { return Bun.resolveSync(p, import.meta.dir); };
__bun_register({
  "./src/a.ts": function (module, exports) {
    module.exports = { val: 1 };
  },
  "./src/b.ts": function (module, exports) {
    var a = __require("./src/a.ts");
    module.exports = { val: a.val + 1 };
  },
  "./src/c.ts": function (module, exports) {
    var b = __require("./src/b.ts");
    module.exports = { val: b.val + 1 };
  }
});
__require("./src/c.ts");
//# sourceMappingURL=bun-bundle.js.map
