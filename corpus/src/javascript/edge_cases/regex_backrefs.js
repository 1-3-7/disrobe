const pattern = /(?<word>\w+) \k<word>/g;
const flagsCheck = /^test/dgimsuy;
const namedCapture = "the quick quick brown fox jumps jumps over".matchAll(pattern);
const matches = [];
for (const m of namedCapture) {
    matches.push({ index: m.index, groups: m.groups });
}
const replaced = "abc123def456".replace(/(\d+)/g, (_, num) => `<${num}>`);
const lookbehind = "USD 100 EUR 200".match(/(?<=USD )(\d+)/);

console.log({
    matchCount: matches.length,
    matches,
    flags: flagsCheck.flags,
    replaced,
    lookbehind: lookbehind?.[0],
});
