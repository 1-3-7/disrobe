import { checksum } from "./math.ts";

export function greet(name) {
  return `hello ${name} #${checksum(name) % 97}`;
}
