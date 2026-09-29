import { greet } from "./lib/greet.js";
import { checksum } from "./lib/math.ts";
import names from "./lib/names.json" with { type: "json" };

for (const name of names) {
  console.log(greet(name), checksum(name));
}
