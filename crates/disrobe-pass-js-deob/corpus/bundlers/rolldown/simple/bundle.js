/* rolldown 1.0.0-beta */
var __rolldown_runtime__ = (function () {
  var modules = {};
  function require(id) { return modules[id](); }
  return { require: require };
})();
__rolldown_modules__ = {
  "./src/a.ts": function (module, exports) { module.exports = { a: 1 }; },
  "./src/b.ts": function (module, exports) {
    var a = require("./src/a.ts");
    module.exports = { b: a.a + 1 };
  },
  "./src/entry.ts": function (module, exports) {
    var b = require("./src/b.ts");
    module.exports = b;
  }
};
import("./chunks/lazy-abc.js");
//# sourceMappingURL=bundle.js.map
