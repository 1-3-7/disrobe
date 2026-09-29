export function checksum(text: string): number {
  let sum: number = 0;
  for (const ch of text) {
    sum = (sum * 31 + ch.charCodeAt(0)) >>> 0;
  }
  return sum;
}
