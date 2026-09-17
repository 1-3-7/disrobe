function tag(strings, ...values) {
    const cooked = strings.join("|");
    const raw = strings.raw.join("|");
    return { cooked, raw, values };
}

const result = tag`a\n${1}b\t${2}c\\${3}d`;
console.log(JSON.stringify(result));
