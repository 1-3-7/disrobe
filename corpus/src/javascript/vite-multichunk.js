const __vitePreload = function (baseModule, deps) {
  return Promise.all(deps.map(function (d) { return import(d); })).then(baseModule);
};
const pages = import.meta.glob('./pages/*.tsx');
const widgets = import.meta.glob('./widgets/*.tsx');
const env = import.meta.env;

export function loadPage(name) {
  return __vitePreload(function () { return pages[name](); }, ['./pages/home.tsx', './pages/about.tsx']);
}

export async function lazyWidget() {
  const w = await import('./widgets/chart.tsx');
  return w;
}

export async function bootstrap() {
  const page = await loadPage('home');
  const widget = await lazyWidget();
  return { page: page, widget: widget };
}
