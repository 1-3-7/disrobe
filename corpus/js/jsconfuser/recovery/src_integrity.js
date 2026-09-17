function add(a, b) {
  return a + b;
}

function mul(a, b) {
  return a * b;
}

var x = Number(process.argv[2]);
var y = Number(process.argv[3]);
console.log(add(x, y));
console.log(mul(x, y));
