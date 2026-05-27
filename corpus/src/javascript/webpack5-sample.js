var __webpack_modules__ = {
  "./src/index.js": function (module, exports, __webpack_require__) {
    var util = __webpack_require__("./src/util.js");
    module.exports = function () { return 'index:' + util(); };
  },
  "./src/util.js": function (module, exports) {
    module.exports = function () { return 'helper'; };
  }
};
var __webpack_module_cache__ = {};
function __webpack_require__(moduleId) {
  if (__webpack_module_cache__[moduleId]) {
    return __webpack_module_cache__[moduleId].exports;
  }
  var module = __webpack_module_cache__[moduleId] = { exports: {} };
  __webpack_modules__[moduleId](module, module.exports, __webpack_require__);
  return module.exports;
}
__webpack_require__.r = function (exports) {
  Object.defineProperty(exports, "__esModule", { value: true });
};
__webpack_require__.d = function (exports, definition) {};
(self.webpackChunkapp = self.webpackChunkapp || []).push([[0], {}]);
__webpack_require__("./src/index.js");
