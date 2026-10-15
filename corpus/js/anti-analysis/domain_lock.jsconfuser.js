globalThis.window = { location: { href: "https://mirror.invalid/app/index.html" } };
function onLockTriggered() {
  console.log("locked: domain lock countermeasure");
  process.exit(0);
}
function fib(n) {
  let a = 0;
  let b = 1;
  for (let i = 0; i < n; i++) {
    [a, b] = [b, a + b];
  }
  return a;
}
function main() {
  if(!new RegExp("^(?:https?:\\/\\/)?(?:[^\\/]+\\.)?example\\.com(?::\\d+)?(?:\\/|$)").test(window.location.href)) { onLockTriggered() }
  console.log("unlocked: fib(30) = " + fib(30));
}
main();
