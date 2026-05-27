 (() => { // webpackBootstrap
 	"use strict";
 	var __webpack_modules__ = ({});


 	var __webpack_module_cache__ = {};


 	function __webpack_require__(moduleId) {

 		var cachedModule = __webpack_module_cache__[moduleId];
 		if (cachedModule !== undefined) {
 			return cachedModule.exports;
 		}

 		var module = __webpack_module_cache__[moduleId] = {


 			exports: {}
 		};


 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);


 		return module.exports;
 	}


 	__webpack_require__.m = __webpack_modules__;


 	(() => {

 		__webpack_require__.d = (exports, definition) => {
 			for(var key in definition) {
 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
 				}
 			}
 		};
 	})();


 	(() => {
 		__webpack_require__.f = {};


 		__webpack_require__.e = (chunkId) => {
 			return Promise.all(Object.keys(__webpack_require__.f).reduce((promises, key) => {
 				__webpack_require__.f[key](chunkId, promises);
 				return promises;
 			}, []));
 		};
 	})();


 	(() => {

 		__webpack_require__.u = (chunkId) => {

 			return "" + chunkId + ".bundle.js";
 		};
 	})();


 	(() => {
 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
 	})();


 	(() => {


 		var installedChunks = {
 			792: 1
 		};


 		var installChunk = (chunk) => {
 			var moreModules = chunk.modules, chunkIds = chunk.ids, runtime = chunk.runtime;
 			for(var moduleId in moreModules) {
 				if(__webpack_require__.o(moreModules, moduleId)) {
 					__webpack_require__.m[moduleId] = moreModules[moduleId];
 				}
 			}
 			if(runtime) runtime(__webpack_require__);
 			for(var i = 0; i < chunkIds.length; i++)
 				installedChunks[chunkIds[i]] = 1;

 		};


 		__webpack_require__.f.require = (chunkId, promises) => {

 			if(!installedChunks[chunkId]) {
 				if(true) {
 					var installedChunk = require("./" + __webpack_require__.u(chunkId));
 					if (!installedChunks[chunkId]) {
 						installChunk(installedChunk);
 					}
 				} else installedChunks[chunkId] = 1;
 			}
 		};


 	})();


var __webpack_exports__ = {};

;// ./src/util.js
const greet = (name) => `hello ${name}`;
const repeat = (s, n) => Array(n).fill(s).join(" ");
class Counter {
  #count = 0;
  inc() {
    this.#count += 1;
    return this.#count;
  }
  get value() {
    return this.#count;
  }
}

;// ./src/math.js
const add = (a, b) => a + b;
const mul = (a, b) => a * b;
const sum = (xs) => xs.reduce(add, 0);
const factorial = (n) => (n <= 1 ? 1 : mul(n, factorial(n - 1)));

;// ./src/index.js


const counter = new Counter();
counter.inc();
counter.inc();

const greeting = greet("world");
const banner = repeat(greeting, 2);

console.log(
  JSON.stringify({
    banner,
    counter: counter.value,
    sum: sum([1, 2, 3, 4, 5]),
    factorial: factorial(5),
  }),
);

async function loadLazy() {
  const mod = await __webpack_require__.e( 899).then(__webpack_require__.bind(__webpack_require__, 899));
  console.log(mod.heavyTag, mod.lazyCompute(3));
}

loadLazy().catch(console.error);

module.exports = __webpack_exports__;
 })()
;
//# sourceMappingURL=bundle.js.map