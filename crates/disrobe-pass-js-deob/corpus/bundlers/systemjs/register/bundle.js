System.register("app/main", ["./util"], function (exports_1, context_1) {
  "use strict";
  var util_1, x;
  return {
    setters: [function (util_1_1) { util_1 = util_1_1; }],
    execute: function () {
      x = util_1.add(1, 2);
      exports_1("x", x);
    }
  };
});
System.register("app/util", [], function (exports_2, context_2) {
  "use strict";
  return {
    setters: [],
    execute: function () {
      exports_2("add", function (a, b) { return a + b; });
    }
  };
});
//# sourceMappingURL=systemjs-bundle.js.map
