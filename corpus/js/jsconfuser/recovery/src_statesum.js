function pipeline(n) {
  var acc = n;
  acc = acc + 5;
  acc = acc * 3;
  acc = acc - 2;
  return acc;
}

function gate(x) {
  var r = x;
  r = r + 100;
  r = r * 2;
  return r;
}

var values = [10, 0, 7, 25];
var collected = [];
for (var i = 0; i < values.length; i++) {
  collected.push(pipeline(values[i]) + ":" + gate(values[i]));
}
console.log(collected.join(","));
