function render(items) {
  return items.map((item, index) => index + ":" + item.toUpperCase()).join(",");
}
function main() {
  if (typeof window === "undefined" || typeof document === "undefined") {
    console.log("locked: not a browser host");
    return;
  }
  if (typeof process !== "undefined" && process.versions != null && process.versions.node != null) {
    throw new Error("locked: node host refused");
  }
  if (typeof navigator !== "undefined" && navigator.webdriver === true) {
    throw new Error("locked: automated browser refused");
  }
  console.log("unlocked: " + render(["alpha", "beta", "gamma"]));
}
main();
