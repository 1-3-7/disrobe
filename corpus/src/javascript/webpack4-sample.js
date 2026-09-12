(function (modules) {
  var installedModules = {};
  function __webpack_require__(moduleId) {
    if (installedModules[moduleId]) return installedModules[moduleId].exports;
    var module = installedModules[moduleId] = { exports: {} };
    modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
    return module.exports;
  }
  return __webpack_require__(0);
})([
  function (module, exports, __webpack_require__) {
    var dep = __webpack_require__(1);
    module.exports = function () { return 'app:' + dep(); };
  },
  function (module, exports) {
    module.exports = function () { return 'utility'; };
  }
]);
