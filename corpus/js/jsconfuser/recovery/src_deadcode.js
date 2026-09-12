function classify(n) {
  if (n > 100) {
    return "big";
  }
  if (n > 10) {
    return "medium";
  }
  return "small";
}

var x = Number(process.argv[2]);
console.log(classify(x));
