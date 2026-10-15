(function (global) {
  var modules = Object.create(null);
  function define(factory, moduleId, dependencyMap) {
    modules[moduleId] = {
      factory: factory,
      dependencyMap: dependencyMap,
      isInitialized: false,
      publicModule: { exports: {} }
    };
  }
  function metroRequire(moduleId) {
    var module = modules[moduleId];
    if (!module) {
      throw new Error('unknown module ' + moduleId);
    }
    if (!module.isInitialized) {
      module.isInitialized = true;
      module.factory(global, metroRequire, metroImportDefault, metroImportAll,
        module.publicModule, module.publicModule.exports, module.dependencyMap);
    }
    return module.publicModule.exports;
  }
  function metroImportDefault(moduleId) {
    var exports = metroRequire(moduleId);
    return exports && exports.__esModule ? exports.default : exports;
  }
  function metroImportAll(moduleId) {
    var exports = metroRequire(moduleId);
    if (exports && exports.__esModule) {
      return exports;
    }
    var all = {};
    for (var key in exports) {
      all[key] = exports[key];
    }
    all.default = exports;
    return all;
  }
  global.__d = define;
  global.__r = metroRequire;
})(typeof globalThis !== 'undefined' ? globalThis : this);
__d(function (global, _$$_REQUIRE, _$$_IMPORT_DEFAULT, _$$_IMPORT_ALL, module, exports, _dependencyMap) {
  var math = _$$_REQUIRE(_dependencyMap[0]);
  var format = _$$_IMPORT_DEFAULT(_dependencyMap[1]);
  var store = _$$_IMPORT_ALL(_dependencyMap[2]);
  store.push('boot');
  print(format(math.add(2, 3)), math.PI, store.default === store.namespace);
  print(store.items().join('|'), typeof module.exports, Object.keys(exports).length);
}, 0, [1, 2, 3]);
__d(function (global, _$$_REQUIRE, _$$_IMPORT_DEFAULT, _$$_IMPORT_ALL, module, exports, _dependencyMap) {
  exports.add = function (a, b) {
    return a + b;
  };
  exports.PI = 3.14;
}, 1, []);
__d(function (global, _$$_REQUIRE, _$$_IMPORT_DEFAULT, _$$_IMPORT_ALL, module, exports, _dependencyMap) {
  Object.defineProperty(exports, '__esModule', { value: true });
  var math = _$$_REQUIRE(_dependencyMap[0]);
  exports.default = function (value) {
    return 'value=' + value + ' twice=' + math.add(value, value);
  };
}, 2, [1]);
__d(function (global, _$$_REQUIRE, _$$_IMPORT_DEFAULT, _$$_IMPORT_ALL, module, exports, _dependencyMap) {
  var items = [];
  module.exports = {
    namespace: module,
    push: function (item) {
      items.push(item);
    },
    items: function () {
      return items.slice();
    }
  };
}, 3, []);
__r(0);
