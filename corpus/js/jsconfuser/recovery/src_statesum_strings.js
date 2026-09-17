function greet(name, count) {
  var out = "";
  var i = 0;
  while (i < count) {
    out = out + "hello " + name + "! ";
    i = i + 1;
  }
  return out.trim();
}

console.log(greet("world", 3));
console.log(greet(process.argv[2], 2));
