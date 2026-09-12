"use strict";
var __defProp = Object.defineProperty;
var __export = (target, all) => { for (var name in all) __defProp(target, name, { get: all[name], enumerable: true }); };
var __commonJS = (cb, mod) => function __require() { return mod || (cb((mod = { exports: {} }).exports, mod), mod), mod.exports; };

var require_util = __commonJS({ "./src/util.js": (exports, module) => {
  module.exports = { hello: () => "hi" };
} });

var require_lib = __commonJS({ "./src/lib.js": (exports, module) => {
  var util = require_util();
  module.exports = { greet: function () { return util.hello() + "!"; } };
} });

var require_index = __commonJS({ "./src/index.js": (exports, module) => {
  var lib = require_lib();
  module.exports = lib.greet();
} });

require_index();
//# sourceMappingURL=bundle.js.map
