async function loadDynamic() {
    const node_fs = await import("node:fs");
    return typeof node_fs.readFileSync === "function";
}

const metaUrl = typeof import.meta !== "undefined" ? import.meta.url ?? "n/a" : "n/a";
loadDynamic().then((ok) => console.log({ dynamicOk: ok, metaUrl }));
