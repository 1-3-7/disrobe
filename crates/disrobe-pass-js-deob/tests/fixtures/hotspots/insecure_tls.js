const https = require("https");
const tls = require("tls");
const host = globalThis.host;

const insecure = https.request({ host, rejectUnauthorized: false }); // Noncompliant {{S4830}}
const socket = tls.connect({ host, port: 443, rejectUnauthorized: false }); // Noncompliant {{S4830}}
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // Noncompliant {{S4830}}
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // Noncompliant {{S4830}}

const secure = https.request({ host, rejectUnauthorized: true });
const verified = tls.connect({ host, port: 443 });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
process.env.HTTP_PROXY = "http://proxy.local";
