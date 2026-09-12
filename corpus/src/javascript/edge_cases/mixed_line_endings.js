const crlf = "line1\r\nline2\r\nline3";
const lf = "alpha\nbeta\ngamma";
const lsep = "one
two
three";
const psep = "para
sep
sep";
const mixed = `${crlf}\n${lf}\r\n${lsep}\r${psep}`;
const tagged = String.raw`back\nslash\r\nlit`;
const splitter = new RegExp("\\r\\n|\\r|\\n|\\u2028|\\u2029");

console.log({
    crlfLen: crlf.length,
    lfLen: lf.length,
    lsepFirstCp: lsep.codePointAt(3),
    psepFirstCp: psep.codePointAt(4),
    mixedLines: mixed.split(splitter).length,
    taggedLen: tagged.length,
});
