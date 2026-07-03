(function classify(n) {
  if (n < 0) return "neg";
  if (n === 0) return "zero";
  return "pos";
})();
(function accumulate(items) {
  let total = 0;
  for (let i = 0; i < items.length; i++) {
    total = total + items[i];
  }
  return total;
})([1, 2, 3]);
(function greet(name) {
  return "hello, " + name + "!";
})("world");
