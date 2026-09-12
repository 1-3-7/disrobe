(self.__next_f = self.__next_f || []).push([0]);
var __turbopack_modules__ = {
  "./app/page.tsx": function (m) { m.exports = { Page: function () { return "page"; } }; },
  "./components/button.tsx": function (m) { m.exports = { Button: function () { return "btn"; } }; }
};
function __turbopack_require__(id) { return __turbopack_modules__[id](); }
function __turbopack_load__(chunkId) { return Promise.resolve(chunkId); }
var __turbopack_export_value__ = function () {};
__turbopack_require__("./app/page.tsx");
__turbopack_require__("./components/button.tsx");
__turbopack_load__("./chunks/lazy.js").then(function () { return null; });
//# sourceMappingURL=turbopack.js.map
