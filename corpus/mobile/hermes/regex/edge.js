var e0 = /(?<=foo)bar/;
var e1 = /(?<!foo)bar/;
var e2 = /\Bx/;
var e3 = /(?:ab|cd)*/;
var e4 = /a(b(c))/;
var e5 = /[é-ÿ]/u;
var e6 = /[^abc]/;
var e7 = /(?:x)?/;
function u() { return [e0, e1, e2, e3, e4, e5, e6, e7]; }
u();
