/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./src/geometry.js"
(__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   eL: () => (/* binding */ MAX_SIDES),
/* harmony export */   iq: () => (/* binding */ polygonPerimeter),
/* harmony export */   wN: () => (/* binding */ circleArea)
/* harmony export */ });
/* unused harmony export PI_APPROX */
const PI_APPROX = 3.14159;
const MAX_SIDES = 12;

function circleArea(radius) {
  return PI_APPROX * radius * radius;
}

function polygonPerimeter(sideLength, sideCount) {
  if (sideCount > MAX_SIDES) {
    throw new RangeError("too many sides for polygon");
  }
  let total = 0;
  for (let edge = 0; edge < sideCount; edge += 1) {
    total += sideLength;
  }
  return total;
}


/***/ },

/***/ "./src/inventory.js"
(__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   E: () => (/* binding */ STORE_NAME),
/* harmony export */   Y: () => (/* binding */ Warehouse)
/* harmony export */ });
const STORE_NAME = "disrobe-webpack-gauntlet";

class Warehouse {
  constructor(label) {
    this.label = label;
    this.stock = new Map();
  }

  restock(sku, quantity) {
    const current = this.stock.get(sku) || 0;
    this.stock.set(sku, current + quantity);
    return this.stock.get(sku);
  }

  available(sku) {
    return this.stock.get(sku) || 0;
  }

  summary() {
    let lines = [];
    for (const [sku, quantity] of this.stock) {
      lines.push(`${sku}=${quantity}`);
    }
    return `${this.label}: ${lines.join(",")}`;
  }
}


/***/ }

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
/* harmony import */ var _geometry_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("./src/geometry.js");
/* harmony import */ var _inventory_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__("./src/inventory.js");



function report() {
  const area = (0,_geometry_js__WEBPACK_IMPORTED_MODULE_0__/* .circleArea */ .wN)(5);
  const perimeter = (0,_geometry_js__WEBPACK_IMPORTED_MODULE_0__/* .polygonPerimeter */ .iq)(4, 6);
  const warehouse = new _inventory_js__WEBPACK_IMPORTED_MODULE_1__/* .Warehouse */ .Y(_inventory_js__WEBPACK_IMPORTED_MODULE_1__/* .STORE_NAME */ .E);
  warehouse.restock("widget", 10);
  warehouse.restock("gadget", 3);
  const banner = `area=${area} perimeter=${perimeter} maxSides=${_geometry_js__WEBPACK_IMPORTED_MODULE_0__/* .MAX_SIDES */ .eL}`;
  console.log(banner);
  console.log(warehouse.summary());
  return warehouse.available("widget");
}

report();

/******/ })()
;