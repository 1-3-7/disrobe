function digest(value) {
  let total = 0;
  for (const ch of value) {
    total = (total * 33 + ch.charCodeAt(0)) % 1000003;
  }
  return total;
}
const phrase = "forensic marker lzstring";
const joined = [phrase, phrase.toUpperCase(), digest(phrase)].join("|");
console.log("lz=" + joined);
