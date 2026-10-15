'use strict';

const fs = require('fs');
const path = require('path');
const util = require('util');

const reference = path.join(__dirname, 'reference');

function load(file, modules) {
  const module = { exports: {} };
  const source = fs.readFileSync(path.join(reference, file), 'utf8');
  const factory = new Function('exports', 'require', 'module', source);
  factory(module.exports, (name) => {
    if (!(name in modules)) {
      throw new Error(file + ' requires ' + name);
    }
    return modules[name];
  }, module);
  return module.exports;
}

const written = [];
const recordingFs = {
  existsSync: () => false,
  mkdir: (directory, options, callback) => callback(null),
  createReadStream: () => ({ pipe: (target) => target }),
  createWriteStream: (destination) => ({
    on: (event, callback) => {
      written.push(destination);
      callback();
    },
  }),
};
const assetUtils = load('AndroidPathUtils.js', {});
const filterPlatformAssetScales = load('filterPlatformAssetScales.js', {});
const getAssetDestPathAndroid = load('getAssetDestPathAndroid.js', {
  '@react-native/asset-utils': assetUtils,
  path: path.posix,
});
const getAssetDestPathIOS = load('getAssetDestPathIOS.js', { path: path.posix });
const saveAssets = load('saveAssets.js', {
  './assetCatalogIOS': {},
  './createKeepFileAsync': { __esModule: true, default: async () => {} },
  './filterPlatformAssetScales': filterPlatformAssetScales,
  './getAssetDestPathAndroid': getAssetDestPathAndroid,
  './getAssetDestPathIOS': getAssetDestPathIOS,
  fs: recordingFs,
  path: path.posix,
  util,
}).default;

async function main() {
  const platform = process.argv[2];
  const assets = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
  const prefix = platform === 'android' ? 'res/' : '';
  console.info = () => {};
  console.warn = () => {};
  const lines = [];
  for (const asset of assets) {
    written.length = 0;
    const files = asset.scales.map((scale, index) => 'source-' + index);
    await saveAssets([Object.assign({}, asset, { files })], platform, 'DEST', undefined);
    const paths = [];
    for (const destination of written) {
      const relative = prefix + path.posix.relative('DEST', destination);
      if (!paths.includes(relative)) {
        paths.push(relative);
      }
    }
    lines.push(JSON.stringify(paths));
  }
  process.stdout.write(lines.join('\n') + '\n');
}

main().catch((error) => {
  process.stderr.write(String(error && error.stack ? error.stack : error) + '\n');
  process.exit(1);
});
