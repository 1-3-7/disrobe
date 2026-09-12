const __vitePreload = function (baseModule, deps) { return baseModule(); };
const mods = import.meta.glob('./pages/*.tsx');
const env = import.meta.env;

export function loadPage(name) {
  return __vitePreload(() => mods[name]());
}

export async function bootstrap() {
  const page = await loadPage('home');
  return page;
}
