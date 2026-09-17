function transform(n) {
  var acc = n;
  acc = acc + 5;
  acc = acc * 3;
  acc = acc - 2;
  return acc;
}

var input = Number(process.argv[2]);
console.log(transform(input));
