var __webpack_modules__ = {
  "./src/main.js": function (module, exports, __webpack_require__) {
    var vendor = __webpack_require__.e("vendor").then(function () { return __webpack_require__("./node_modules/lib/index.js"); });
    module.exports = "main:" + vendor;
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
(self.webpackChunkapp = self.webpackChunkapp || []).push([[0], { "./src/main.js": __webpack_modules__["./src/main.js"] }]);
(self.webpackChunkapp = self.webpackChunkapp || []).push([[42], { "./node_modules/lib/index.js": function (m, e, r) { m.exports = "vendor-lib"; } }]);
__webpack_require__("./src/main.js");
