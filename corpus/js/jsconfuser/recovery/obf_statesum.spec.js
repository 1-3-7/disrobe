function pipeline(n) {
  var acc = n;
  var s0 = 2, s1 = 3, s2 = 5;
  while (s0 + s1 + s2 !== 99) {
    switch (s0 + s1 + s2) {
      case 10:
        acc = acc + 5;
        s0 += 4, s1 += 3, s2 += 3;
        break;
      case s0 - -14:
        acc = acc * 3;
        s0 += 5, s1 += 5, s2 += 5;
        break;
      case s1 + 24:
        acc = acc - 2;
        s0 += 5, s1 += 5, s2 += 5;
        break;
      case s2 + 32:
        return acc;
    }
  }
}

function gate(x) {
  var r = x;
  var t0 = 1, t1 = 4;
  while (t0 + t1 !== 88) {
    switch (t0 + t1) {
      case 5:
        r = r + 100;
        t0 += 3, t1 += 4;
        break;
      case t1 + 4:
        r = r * 2;
        t0 += 4, t1 += 4;
        break;
      case t0 + 12:
        return r;
    }
  }
}

var values = [10, 0, 7, 25];
var collected = [];
for (var i = 0; i < values.length; i++) {
  collected.push(pipeline(values[i]) + ":" + gate(values[i]));
}
console.log(collected.join(","));
