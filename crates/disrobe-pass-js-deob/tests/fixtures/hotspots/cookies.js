const token = globalThis.token;

function register(res) {
  res.cookie("sid", token, { httpOnly: true }); // Noncompliant {{S2092}}
  res.cookie("csrf", token, { secure: true }); // Noncompliant {{S3330}}
  res.cookie("legacy", token, {}); // Noncompliant {{S3330}} {{S2092}}
  res.cookie("mixed", token, { httpOnly: false, secure: false }); // Noncompliant {{S3330}} {{S2092}}

  res.cookie("safe", token, { httpOnly: true, secure: true });
  res.cookie("also", token, { secure: true, httpOnly: true, sameSite: "strict" });
}
