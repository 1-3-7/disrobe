var r0 = /abc/;
var r1 = /^abc$/g;
var r2 = /a.c/i;
var r3 = /\d+/;
var r4 = /[a-z]+/;
var r5 = /[^0-9]/;
var r6 = /(foo)(bar)/;
var r7 = /a|b|c/;
var r8 = /colou?r/;
var r9 = /a{2,5}/;
var r10 = /\bword\b/;
var r11 = /(?:abc)+/;
var r12 = /foo(?=bar)/;
var r13 = /foo(?!bar)/;
var r14 = /(\w)\1/;
var r15 = /\s*\S+/;
var r16 = /ab*c/;
var r17 = /x{3}/gi;
var r18 = /a+?/;
var r19 = /[A-Za-z0-9_]/;
var r20 = /hello world/;
var r21 = /\./;
var r22 = /[\d\s]/;

function useThem() {
  return [
    r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11,
    r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22,
  ];
}

useThem();
