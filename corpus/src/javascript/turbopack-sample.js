var __turbopack_require__ = function (moduleId) { return __turbopack_modules__[moduleId]; };
var __turbopack_load__ = function (chunkId) { return Promise.resolve(); };
var __turbopack_export_value__ = function (target, value) { Object.defineProperty(target, 'default', { value: value }); };

__turbopack_modules__ = {
  "./app/page.tsx": function (module, exports) {
    module.children = [];
    module.exports = function Page() { return 'page-content'; };
  },
  "./app/layout.tsx": function (module, exports) {
    module.children = [];
    module.exports = function Layout(props) { return props.children; };
  }
};

__turbopack_require__("./app/page.tsx");
