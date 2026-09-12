function sumTo(n) {
  var acc = 0;
  var i = 1;
  while (i <= n) {
    acc = acc + i;
    i = i + 1;
  }
  return acc;
}

var input = Number(process.argv[2]);
console.log(sumTo(input));
