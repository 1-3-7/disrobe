import { createCipheriv } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const source = await readFile(new URL("./crafted_modern_aesgcm_known_key.py", import.meta.url));
if (source.length === 0 || source.length > 255) {
  throw new RangeError("the authored source must fit the fixture's msgpack str8 field");
}

const payload = Buffer.concat([
  Buffer.from([0x82, 0xad]),
  Buffer.from("original_code"),
  Buffer.from([0xd9, source.length]),
  source,
  Buffer.from([0xad]),
  Buffer.from("eol_timestamp"),
  Buffer.from([0]),
]);
const salt = Buffer.alloc(16, 0x11);
const nonce = Buffer.alloc(12, 0x22);
const key = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
const cipher = createCipheriv("aes-256-gcm", key, nonce);
const sealed = Buffer.concat([salt, nonce, cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
const hex = sealed.toString("hex").toUpperCase();
const lines = hex.match(/.{1,40}/g);
if (lines === null) {
  throw new Error("the AES-GCM frame must contain a body");
}
const output = Buffer.from(`---BEGIN PYE FILE---\n${lines.join("\n")}\n----END PYE FILE----\n`);
const fixture = new URL("./crafted_modern_aesgcm_known_key.pye", import.meta.url);
if (process.argv[2] === "--check") {
  const recorded = await readFile(fixture);
  if (!recorded.equals(output)) {
    throw new Error("the recorded known-key AES-GCM fixture differs from the authored source");
  }
} else if (process.argv.length === 2) {
  await writeFile(fixture, output);
} else {
  throw new Error("usage: node build_crafted_modern.mjs [--check]");
}
