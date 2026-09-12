const crypto = require("crypto");
const CryptoJS = require("crypto-js");
const data = globalThis.data;
const key = globalThis.key;
const iv = globalThis.iv;

crypto.createHash("md5").update(data).digest("hex"); // Noncompliant {{S4790}}
crypto.createHash("sha1").update(data).digest("hex"); // Noncompliant {{S4790}}
CryptoJS.MD5(data); // Noncompliant {{S4790}}
CryptoJS.SHA1(data); // Noncompliant {{S4790}}
crypto.createCipheriv("des-cbc", key, iv); // Noncompliant {{S5547}}
crypto.createCipheriv("rc4", key, iv); // Noncompliant {{S5547}}
crypto.createCipheriv("aes-128-ecb", key, iv); // Noncompliant {{S5542}}
crypto.createCipheriv("des-ecb", key, iv); // Noncompliant {{S5547}} {{S5542}}
CryptoJS.DES.encrypt(data, key); // Noncompliant {{S5547}}
CryptoJS.RC4.encrypt(data, key); // Noncompliant {{S5547}}

crypto.createHash("sha256").update(data).digest("hex");
crypto.createHash("sha512");
crypto.createCipheriv("aes-256-gcm", key, iv);
CryptoJS.SHA256(data);
CryptoJS.AES.encrypt(data, key);
