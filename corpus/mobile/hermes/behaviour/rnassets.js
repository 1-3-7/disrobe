var __modules = {};

function __d(factory, id, dependencies) {
  __modules[id] = { factory: factory, dependencies: dependencies, exports: undefined, done: false };
}

function __r(id) {
  var record = __modules[id];
  if (!record.done) {
    record.done = true;
    var module = { exports: {} };
    record.factory(globalThis, __r, null, null, module, module.exports, record.dependencies);
    record.exports = module.exports;
  }
  return record.exports;
}

__d(function (global, require, importDefault, importAll, module, exports, dependencyMap) {
  var assets = [];
  module.exports = {
    registerAsset: function (asset) {
      return assets.push(asset);
    },
    getAssetByID: function (id) {
      return assets[id - 1];
    },
    all: assets
  };
}, 0, []);

__d(function (global, require, importDefault, importAll, module, exports, dependencyMap) {
  module.exports = require(dependencyMap[0]).registerAsset({
    "__packager_asset": true,
    "httpServerLocation": "/assets/src/images",
    "width": 24,
    "height": 24,
    "scales": [1, 2, 3],
    "hash": "6a1bf3c0e1a2b3c4d5e6f708192a3b4c",
    "name": "logo",
    "type": "png"
  });
}, 1, [0]);

__d(function (global, require, importDefault, importAll, module, exports, dependencyMap) {
  module.exports = require(dependencyMap[0]).registerAsset({
    "__packager_asset": true,
    "httpServerLocation": "/assets/node_modules/@scope/icons/assets",
    "width": 16,
    "height": 16,
    "scales": [1, 1.5, 2, 3, 4],
    "hash": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "name": "Icon-Back",
    "type": "webp"
  });
}, 2, [0]);

__d(function (global, require, importDefault, importAll, module, exports, dependencyMap) {
  module.exports = require(dependencyMap[0]).registerAsset({
    "__packager_asset": true,
    "httpServerLocation": "/assets/fonts",
    "scales": [1],
    "hash": "11223344556677889900aabbccddeeff",
    "name": "Inter-Bold",
    "type": "ttf"
  });
}, 3, [0]);

__d(function (global, require, importDefault, importAll, module, exports, dependencyMap) {
  module.exports = require(dependencyMap[0]).registerAsset({
    "__packager_asset": true,
    "httpServerLocation": "/assets/../shared/img",
    "width": 320,
    "height": 180,
    "scales": [0.75, 2.5],
    "hash": "ffeeddccbbaa00998877665544332211",
    "name": "splash bg",
    "type": "jpg"
  });
}, 4, [0]);

__d(function (global, require, importDefault, importAll, module, exports, dependencyMap) {
  var registry = require(dependencyMap[0]);
  var ids = [require(dependencyMap[1]), require(dependencyMap[2]), require(dependencyMap[3]), require(dependencyMap[4])];
  print(ids.join(','));
  print(JSON.stringify(registry.all));
  print(registry.getAssetByID(ids[1]).name);
}, 5, [0, 1, 2, 3, 4]);

__r(5);
