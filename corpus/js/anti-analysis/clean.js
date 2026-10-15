const root = typeof window !== "undefined" ? window : globalThis;
function route(hostname) {
  if (hostname === "docs.example.com") {
    return "docs";
  }
  return "app";
}
function start() {
  const host = root.location && root.location.hostname ? root.location.hostname : "localhost";
  console.log("route " + route(host));
}
if (typeof window !== "undefined") {
  window.addEventListener("load", start);
} else {
  start();
}
if (typeof process !== "undefined" && process.argv.length > 99) {
  console.log("many arguments");
}
const stamp = new Date(0).getTime();
if (Date.now() > stamp) {
  console.log("clock after epoch");
}
const methods = ["log", "warn", "info", "error", "exception", "table", "trace"];
const sink = {};
for (let i = 0; i < methods.length; i++) {
  sink[methods[i]] = console.log.bind(console);
}
console.log("note: the word debugger is only text here; " + "debu" + "gger" + " " + methods.length);
