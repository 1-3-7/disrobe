// modules are defined as an array
(function () {
  var globalObject = "undefined" != typeof globalThis ? globalThis : self;
  var parcelRequire = globalObject["parcelRequire"] = function (id) {
    return parcelRequire.cache[id]();
  };
  parcelRequire.cache = {};
  parcelRequire.register = function (id, fn) { parcelRequire.cache[id] = fn; };

  parcelRequire.register("aaaaa", function (module, exports) {
    module.exports = { name: "alpha" };
  });
  parcelRequire.register("bbbbb", function (module, exports) {
    var a = parcelRequire("aaaaa");
    module.exports = { name: a.name + "-beta" };
  });
  parcelRequire.register("ccccc", function (module, exports) {
    module.exports = parcelRequire("bbbbb");
  });
})();
//# sourceMappingURL=index.abc.js.map
