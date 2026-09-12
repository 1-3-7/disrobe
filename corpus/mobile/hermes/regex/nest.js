var n0 = /(ab)+/;
var n1 = /(a|b)c/;
var n2 = /(x+)y/;
var n3 = /a(?:b|c)*d/;
var n4 = /((a)(b))+/;
var n5 = /^(\d{3})-(\d{4})$/;
var n6 = /(foo)+bar(baz)?/;
function u() { return [n0, n1, n2, n3, n4, n5, n6]; }
u();
