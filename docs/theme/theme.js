(() => {
  const root = document.documentElement;
  document.addEventListener("keydown", (event) => {
    if ((event.key === "ArrowLeft" || event.key === "ArrowRight") &&
        event.target instanceof Element && event.target.closest(".table-scroll, pre")) {
      event.stopPropagation();
    }
  }, true);
  for (const table of document.querySelectorAll("main table")) {
    const headers = [...table.querySelectorAll("thead th")];
    const rows = [...table.querySelectorAll("tbody tr")];
    const simple = headers.length > 0 && headers.length <= 3 &&
      rows.every((row) => row.cells.length === headers.length && [...row.cells].every((cell) => cell.colSpan === 1 && cell.rowSpan === 1));
    for (const header of headers) header.scope = "col";
    if (simple) {
      table.classList.add("responsive-table");
      for (const row of rows) {
        [...row.cells].forEach((cell, index) => {
          const label = document.createElement("span");
          label.className = "table-label";
          label.setAttribute("aria-hidden", "true");
          label.textContent = headers[index].textContent;
          cell.prepend(label);
        });
      }
    } else {
      const region = document.createElement("div");
      region.className = "table-scroll";
      region.tabIndex = 0;
      region.setAttribute("role", "region");
      region.setAttribute("aria-label", "Table; scroll horizontally for additional columns");
      table.before(region);
      region.append(table);
    }
  }
  const picker = document.createElement("select");
  picker.id = "color-theme";
  picker.setAttribute("aria-label", "Color theme");
  picker.add(new Option("Dark", "ayu"));
  picker.add(new Option("Light", "light"));
  document.getElementById("theme-toggle").replaceWith(picker);
  document.getElementById("theme-list").remove();

  function restricted(error) {
    return error instanceof DOMException &&
      (error.name === "SecurityError" || error.name === "QuotaExceededError");
  }

  function apply(value) {
    const theme = value === "light" || value === "rust" ? "light" : "ayu";
    root.classList.remove("light", "rust", "coal", "navy", "ayu");
    root.classList.add(theme);
    picker.value = theme;
    document.querySelector('[href$="highlight.css"]:not([href$="ayu-highlight.css"])').disabled = theme !== "light";
    document.querySelector('[href$="ayu-highlight.css"]').disabled = theme !== "ayu";
    document.querySelector('[href$="tomorrow-night.css"]').disabled = true;
    document.querySelector('meta[name="theme-color"]').content = getComputedStyle(root).backgroundColor;
  }

  apply(root.classList.contains("light") || root.classList.contains("rust") ? "light" : "ayu");
  picker.addEventListener("change", () => {
    apply(picker.value);
    try {
      localStorage.setItem("mdbook-theme", picker.value);
      picker.removeAttribute("title");
    } catch (error) {
      if (!restricted(error)) throw error;
      picker.title = "Theme applies for this visit.";
    }
  });
  window.addEventListener("storage", (event) => {
    if (event.key !== null && event.key !== "mdbook-theme") return;
    try {
      if (event.storageArea === localStorage) apply(event.newValue);
    } catch (error) {
      if (!restricted(error)) throw error;
    }
  });
})();
