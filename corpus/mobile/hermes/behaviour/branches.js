var calls = [];

function touch(tag, value) {
  calls.push(tag);
  return value;
}

function interopDefault(e) {
  return e && e.__esModule ? e : { default: e };
}

function defaultTo(value, fallback) {
  return value == null || value !== value ? fallback : value;
}

function plural(kind) {
  return kind === "few" || kind === "one" ? "few" : "other";
}

function pick(a, b, c) {
  return (a && b) || c ? (a ? "a" : "b") : "none";
}

function nullish(a, b) {
  var x = a ?? b;
  return x?.length ?? -1;
}

function order(a, b, c) {
  return touch("a", a) || (touch("b", b) && touch("c", c)) ? touch("t", 1) : touch("f", 0);
}

function nestedTernary(x) {
  return x > 10 ? (x > 100 ? "huge" : "big") : x < 0 || x !== x ? "bad" : "small";
}

function firstMatch(list, pred) {
  outer: for (var i = 0; i < list.length; i++) {
    var item = list[i];
    if (item == null || item.skip) continue;
    for (var j = 0; j < item.values.length; j++) {
      if (pred(item.values[j]) || item.values[j] === "stop") {
        if (item.values[j] === "stop") break outer;
        return item.values[j];
      }
    }
  }
  return null;
}

function classify(code) {
  var out = [];
  switch (code) {
    case 1:
      out.push("one");
    case 2:
      out.push("two");
      break;
    case 3:
      if (out.length === 0 || code > 5) {
        out.push("three");
        break;
      }
    case 4:
      out.push("four");
    default:
      out.push("other");
  }
  return out.join("+");
}

function retry(attempts, fail) {
  var log = [];
  for (var i = 0; i < attempts; i++) {
    try {
      if (fail(i) || i === 2) {
        log.push("fail" + i);
        continue;
      }
      log.push("ok" + i);
      if (i > 3) break;
    } finally {
      log.push("f" + i);
    }
  }
  return log.join(",");
}

function shape(o) {
  return o && o.kind === "circle"
    ? 3 * o.r * o.r
    : o && (o.kind === "rect" || o.kind === "square")
      ? o.w * (o.h || o.w)
      : 0;
}

function findKey(obj, test) {
  for (var k in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, k) || k[0] === "_") continue;
    if (test(obj[k], k) && k !== "skip") return k;
  }
  return undefined;
}

function collatz(n) {
  var steps = 0;
  while (n > 1 && (steps < 100 || n % 2 === 0)) {
    n = n % 2 === 0 ? n / 2 : 3 * n + 1;
    steps++;
  }
  return steps;
}

function marks(a) {
  var i = 0;
  var s = "";
  do {
    if (a[i] === undefined || a[i] === null) {
      s += "-";
    } else if ((typeof a[i] === "number" && a[i] > 0) || a[i] === "x") {
      s += "+";
    } else {
      s += "?";
    }
    i++;
  } while (i < a.length && s.length < 10);
  return s;
}

function guard(value, strict) {
  if (value === undefined || (strict && value === null)) {
    return "missing";
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return strict || typeof value === "string" ? "scalar" : "loose";
  }
  return Object.keys(value).length > 0 && !value.empty ? "object" : "empty";
}

var module1 = { __esModule: true, v: 1 };
print(interopDefault(module1) === module1, interopDefault(5).default, interopDefault(null).default);
print(defaultTo(undefined, 1), defaultTo(null, 2), defaultTo(NaN, 3), defaultTo(0, 4), defaultTo("x", 5));
print(plural("few"), plural("one"), plural("many"));
print(pick(1, 1, 0), pick(0, 1, 1), pick(1, 0, 0), pick(0, 0, 1), pick(1, 0, 1));
print(nullish(null, "ab"), nullish("abc", "z"), nullish(undefined, undefined), nullish(0, [1, 2]));
calls = [];
print(order(0, 1, 1), order(0, 0, 1), order(1, 0, 0), order(0, 1, 0), calls.join(""));
print(nestedTernary(5), nestedTernary(50), nestedTernary(500), nestedTernary(-1), nestedTernary(NaN));
var lists = [
  [null, { skip: true, values: [9] }, { values: [1, 2, 3] }],
  [{ values: [1, "stop", 8] }, { values: [8] }],
  [{ values: [] }, { values: [1] }],
];
for (var t = 0; t < lists.length; t++) {
  print(firstMatch(lists[t], function (v) { return v > 1; }));
}
print(classify(1), classify(2), classify(3), classify(4), classify(9));
print(retry(6, function (i) { return i === 0; }));
print(retry(3, function () { return false; }));
print(shape({ kind: "circle", r: 2 }), shape({ kind: "rect", w: 2, h: 3 }), shape({ kind: "square", w: 4 }), shape(null), shape({ kind: "x" }));
print(findKey({ _a: 1, b: 2, skip: 3, c: 4 }, function (v) { return v > 1; }), findKey({ a: 1 }, function () { return false; }));
print(collatz(1), collatz(6), collatz(27), collatz(97));
print(marks([1, null, "x", -1, undefined, 3]), marks([]), marks([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]));
print(guard(undefined, false), guard(null, true), guard(null, false), guard("s", false), guard(3, false), guard(3, true), guard([1], false), guard({}, false), guard({ a: 1 }, false), guard({ a: 1, empty: true }, true));
