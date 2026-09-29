export function checksum(text) {
  let sum = 0;
  for (const ch of text){
    sum = sum * 31 + ch.charCodeAt(0) >>> 0;
  }
  return sum;
}
