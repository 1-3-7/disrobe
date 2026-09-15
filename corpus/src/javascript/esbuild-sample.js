var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all) __defProp(target, name, { get: all[name], enumerable: true });
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

var require_index = __commonJS({
  "./src/index.js": (exports, module) => {
    var util = require_util();
    module.exports = function () { return 'index:' + util(); };
  }
});

var require_util = __commonJS({
  "./src/util.js": (exports, module) => {
    module.exports = function () { return 'helper'; };
  }
});

require_index();
