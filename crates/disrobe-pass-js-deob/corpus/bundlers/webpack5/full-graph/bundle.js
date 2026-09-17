var __webpack_modules__ = {
  "./src/index.js": function (module, exports, __webpack_require__) {
    var util = __webpack_require__("./src/util.js");
    var lib = __webpack_require__("./node_modules/lib/index.js");
    module.exports = util.hello() + " " + lib.tag;
  },
  "./src/util.js": function (module, exports, __webpack_require__) {
    module.exports = { hello: function () { return "hi"; } };
  }
};
var __webpack_module_cache__ = {};
function __webpack_require__(id) {
  if (__webpack_module_cache__[id]) return __webpack_module_cache__[id].exports;
  var module = __webpack_module_cache__[id] = { exports: {} };
  __webpack_modules__[id](module, module.exports, __webpack_require__);
  return module.exports;
}
__webpack_require__.r = function (e) { Object.defineProperty(e, "__esModule", { value: true }); };
__webpack_require__.d = function (e, d) {};
__webpack_require__.e = function (chunkId) { return Promise.resolve(chunkId); };
(self.webpackChunkapp = self.webpackChunkapp || []).push([[42], { "./node_modules/lib/index.js": function (m, e, r) { m.exports = { tag: "vendor" }; } }]);
__webpack_require__.e("lazy-chunk").then(function () { return __webpack_require__("./src/lazy.js"); });
__webpack_require__("./src/index.js");
//# sourceMappingURL=bundle.js.map
