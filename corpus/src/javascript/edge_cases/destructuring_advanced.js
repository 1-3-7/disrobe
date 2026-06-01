const source = {
    user: { id: 7, name: "ada", address: { city: "london", zip: "EC1" } },
    items: [10, 20, 30, 40, 50],
    options: undefined,
};

const {
    user: { id: userId, name: userName, address: { city: cityName, zip: zipCode = "n/a" } },
    items: [first, , third, ...restItems],
    options: { theme = "light", lang = "en" } = {},
} = source;

function fn({ a = 1, b: { c = 3 } = {}, ...rest } = {}) {
    return { a, c, rest };
}

console.log({ userId, userName, cityName, zipCode, first, third, restItems, theme, lang, fn: fn({ a: 9, b: { c: 11 }, x: 1, y: 2 }) });
