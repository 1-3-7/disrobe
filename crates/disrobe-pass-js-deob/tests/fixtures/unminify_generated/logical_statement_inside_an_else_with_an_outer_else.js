var l = 0;
function run(a, b) {
  if (a) if (b) console.log("b"); else l && l-- || (l++, l = 17); else console.log("q");
  console.log(l);
}
run(true, false);
run(false, false);
run(true, true);
run(true, false);
