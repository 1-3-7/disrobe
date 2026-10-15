function classify(n) {
  if (n < 0) return 'negative';
  else if (n === 0) return 'zero';
  else if (n < 10) return 'small';
  return 'large';
}

function dense(k) {
  switch (k) {
    case 0: return 'zero';
    case 1: return 'one';
    case 2: return 'two';
    case 3: return 'three';
    case 4: return 'four';
    case 5: return 'five';
    default: return 'other';
  }
}

function sparse(s) {
  var out = '';
  switch (s) {
    case 'a': out += 'A';
    case 'b': out += 'B'; break;
    case 'c': out += 'C'; break;
    default: out += '?';
  }
  return out;
}

function loops(limit) {
  var total = 0;
  var i = 0;
  while (i < limit) {
    if (i % 3 === 0) { i++; continue; }
    total += i;
    i++;
  }
  var j = limit;
  do {
    total -= j;
    j -= 2;
  } while (j > 0);
  for (var k = 0; k < limit; k++) {
    if (k === 7) break;
    total += k * 2;
  }
  return total;
}

function nested(n) {
  var hits = [];
  outer: for (var a = 0; a < n; a++) {
    for (var b = 0; b < n; b++) {
      if (b > a) continue outer;
      if (a + b === 5) break outer;
      hits.push(a * 10 + b);
    }
  }
  return hits.join(',');
}

function logic(x, y) {
  var a = x && y;
  var b = x || y;
  var c = x ?? 'default';
  var d = !x ? 'not' : 'yes';
  var e = (x, y);
  return [a, b, c, d, e].map(String).join('|');
}

function collatz(n) {
  var steps = 0;
  while (n !== 1) {
    n = n % 2 === 0 ? n / 2 : 3 * n + 1;
    steps++;
  }
  return steps;
}

print(classify(-4), classify(0), classify(7), classify(70));
for (var q = -1; q < 8; q++) print(q, dense(q));
print(sparse('a'), sparse('b'), sparse('c'), sparse('z'));
print(loops(12), loops(5), loops(0));
print(nested(4), nested(9));
print(logic(0, 1), logic(2, 3), logic(null, 'y'), logic(undefined, 0));
print(collatz(27), collatz(1), collatz(97));
var acc = 0;
for (var w = 0; w < 50; w += 7) { acc = acc * 3 + w; if (acc > 1000) acc -= 999; }
print(acc);
