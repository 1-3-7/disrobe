define("my/lib/core", ["jquery", "lodash"], function ($, _) {
  return {
    version: "1.0.0",
    init: function () { return $.fn ? "ok" : "fail"; }
  };
});
define("my/lib/util", [], function () {
  return {
    add: function (a, b) { return a + b; }
  };
});
//# sourceMappingURL=amd-bundle.js.map
