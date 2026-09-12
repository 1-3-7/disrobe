System.register("fixture/main", ["@fixture/math-utils", "@fixture/text-format"], function (_export, _context) {
  "use strict";

  var sum, format;
  return {
    setters: [function (_fixtureMathUtils) {
      sum = _fixtureMathUtils.sum;
    }, function (_fixtureTextFormat) {
      format = _fixtureTextFormat.default;
    }],
    execute: function () {
      globalThis.__result = format(sum(20, 22));
    }
  };
});
