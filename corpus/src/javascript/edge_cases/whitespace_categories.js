const probe = "	

     
  　﻿";
const trimmed = probe.trim();
const length = probe.length;
const codePoints = [...probe].map((ch) => ch.codePointAt(0).toString(16));
const split = probe.split(/\s+/u).filter(Boolean);

console.log({ length, trimmed: trimmed.length, splitCount: split.length, codePoints });
