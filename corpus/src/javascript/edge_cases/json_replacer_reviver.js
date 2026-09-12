const value = {
    id: 1,
    secret: "hidden",
    nested: { secret: "deep", visible: 42 },
    when: new Date(0),
    big: 9007199254740993n,
};

const serialized = JSON.stringify(
    value,
    (key, val) => {
        if (key === "secret") return undefined;
        if (typeof val === "bigint") return `bigint:${val.toString()}`;
        if (val instanceof Date) return `date:${val.toISOString()}`;
        return val;
    },
    2,
);

const revived = JSON.parse(serialized, (key, val) => {
    if (typeof val === "string" && val.startsWith("bigint:")) return BigInt(val.slice(7));
    if (typeof val === "string" && val.startsWith("date:")) return new Date(val.slice(5));
    return val;
});

console.log({ serializedHasSecret: serialized.includes("hidden"), revivedBig: typeof revived.big });
