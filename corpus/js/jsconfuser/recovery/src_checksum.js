function adler32(input) {
  var a = 1;
  var b = 0;
  for (var i = 0; i < input.length; i++) {
    a = (a + input.charCodeAt(i)) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function band(value) {
  if (value > 2000000000) {
    return "huge";
  } else if (value > 1000000000) {
    return "large";
  } else if (value > 100000000) {
    return "medium";
  }
  return "small";
}

function report(word) {
  var sum = adler32(word);
  return word + "=" + sum + ":" + band(sum);
}

var samples = ["alpha", "forensic", "deobfuscate", "z"];
var lines = [];
for (var j = 0; j < samples.length; j++) {
  lines.push(report(samples[j]));
}
console.log(lines.join("|"));
