function pick(n) {
  switch (n) {
    case 0: return "a0";
    case 1: return "a1";
    case 2: return "a2";
    case 3: return "a3";
    case 4: return "a4";
    case 5: return "a5";
    case 6: return "a6";
    case 7: return "a7";
    case 8: return "a8";
    case 9: return "a9";
    case 10: return "b0";
    case 11: return "b1";
    case 12: return "b2";
    case 13: return "b3";
    case 14: return "b4";
    case 15: return "b5";
    default: return "zz";
  }
}

function classify(n) {
  switch (n) {
    case 0:
      return "zero";
    case 1:
      return "one";
    case 2:
      return "two";
    default:
      return "many";
  }
}

function firstPair(limit) {
  var found = 0;
  outer: for (var i = 1; i < limit; i = i + 1) {
    for (var j = i; j < limit; j = j + 1) {
      if (i * j === 12) {
        found = i * 100 + j;
        break outer;
      }
      if (j > 6) {
        continue outer;
      }
    }
  }
  return found;
}

function countDown(n) {
  var acc = 0;
  do {
    acc = acc + n;
    n = n - 1;
  } while (n > 0);
  return acc;
}

function guarded(a, b) {
  var out = 0;
  try {
    if (b === 0) {
      throw new Error("zero");
    }
    out = a - b;
  } catch (e) {
    out = -1;
  }
  return out + 100;
}

function grade(score) {
  return score > 89 ? "a" : score > 79 ? "b" : "f";
}

function bits(mask) {
  var count = 0;
  while (mask !== 0) {
    count = count + (mask & 1);
    mask = mask >>> 1;
  }
  return count;
}

function makeAdder(k) {
  return function (v) {
    return v + k;
  };
}

function total(values) {
  var sum = 0;
  for (var i = 0; i < values.length; i = i + 1) {
    sum = sum + values[i];
  }
  return sum;
}

function names(o) {
  var out = "";
  for (var k in o) {
    out = out + k;
  }
  return out;
}

print(pick(0));
print(pick(15));
print(pick(99));
print(classify(1));
print(firstPair(9));
print(countDown(5));
print(guarded(9, 4));
print(guarded(1, 0));
print(grade(95));
print(grade(72));
print(bits(1023));
print(makeAdder(7)(35));
print(total([1, 2, 3, 4, 5]));
print(names({ a: 1, b: 2, c: 3 }));
