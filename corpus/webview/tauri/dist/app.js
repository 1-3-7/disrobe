import { deep } from "/assets/deep/nested.js";
export function mount(el) {
  el.textContent = deep(41) + 1;
}
mount(document.getElementById("root"));
//# sourceMappingURL=/app.js.map
