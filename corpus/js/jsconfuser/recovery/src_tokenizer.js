function tokenize(expr) {
  var tokens = [];
  var i = 0;
  while (i < expr.length) {
    var ch = expr[i];
    if (ch === " ") {
      i = i + 1;
      continue;
    }
    if (ch >= "0" && ch <= "9") {
      var num = "";
      while (i < expr.length && expr[i] >= "0" && expr[i] <= "9") {
        num = num + expr[i];
        i = i + 1;
      }
      tokens.push("NUM(" + num + ")");
      continue;
    }
    if (ch === "+" || ch === "-" || ch === "*" || ch === "/") {
      tokens.push("OP(" + ch + ")");
      i = i + 1;
      continue;
    }
    tokens.push("BAD(" + ch + ")");
    i = i + 1;
  }
  return tokens;
}

function evaluate(tokens) {
  var acc = 0;
  var op = "+";
  for (var k = 0; k < tokens.length; k++) {
    var t = tokens[k];
    if (t.indexOf("NUM(") === 0) {
      var n = parseInt(t.slice(4, t.length - 1), 10);
      if (op === "+") acc = acc + n;
      else if (op === "-") acc = acc - n;
      else if (op === "*") acc = acc * n;
      else if (op === "/") acc = acc / n;
    } else if (t.indexOf("OP(") === 0) {
      op = t.slice(3, 4);
    }
  }
  return acc;
}

var inputs = ["12 + 30 - 2", "4 * 5 + 100", "9 / 3"];
var out = [];
for (var m = 0; m < inputs.length; m++) {
  var tks = tokenize(inputs[m]);
  out.push(inputs[m] + " => " + tks.join(",") + " = " + evaluate(tks));
}
console.log(out.join("\n"));
