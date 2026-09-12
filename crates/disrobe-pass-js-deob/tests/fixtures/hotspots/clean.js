const crypto = require("crypto");
const data = globalThis.data;
const key = globalThis.key;
const iv = globalThis.iv;

function digest(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function encrypt(plaintext) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return cipher.update(plaintext, "utf8", "hex") + cipher.final("hex");
}

function schedule(handler) {
  setTimeout(handler, 250);
  setInterval(() => handler(), 1000);
}

function render(el, text) {
  el.textContent = text;
  el.setAttribute("data-value", text);
}

function connect(host) {
  return require("https").request({ host, rejectUnauthorized: true });
}

function setSession(res, token) {
  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "strict" });
}

module.exports = { digest, encrypt, schedule, render, connect, setSession };
