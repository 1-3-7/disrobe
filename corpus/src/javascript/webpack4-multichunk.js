(function (modules) {
  function __webpack_require__(moduleId) {
    return modules[moduleId];
  }
  __webpack_require__.e = function (chunkId) {
    return Promise.resolve(chunkId);
  };
  return __webpack_require__(0);
})([
  function (module, exports, __webpack_require__) {
    __webpack_require__.e(1).then(function () { return __webpack_require__("./b.js"); });
    __webpack_require__.e(2).then(function () { return __webpack_require__("./c.js"); });
    module.exports = "entry-a";
  },
  function (module, exports) {
    module.exports = "second";
  },
  function (module, exports) {
    module.exports = "third";
  }
]);
window.webpackJsonp = window.webpackJsonp || [];
window.webpackJsonp.push([[1], { "./b.js": function (m, e, r) { m.exports = "lazy-b"; } }]);
window.webpackJsonp.push([[2], { "./c.js": function (m, e, r) { m.exports = "lazy-c"; } }]);
//# sourceMappingURL=webpack4-multichunk.js.map
