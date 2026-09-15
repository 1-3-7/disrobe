const accessLog = [];
const obj = {
    _x: 1,
    get x() {
        accessLog.push("get-x");
        return this._x;
    },
    set x(v) {
        accessLog.push("set-x");
        if (v < 0) throw new RangeError("negative");
        this._x = v;
    },
};

Object.defineProperty(obj, "doubled", {
    get() { accessLog.push("get-doubled"); return this._x * 2; },
    enumerable: false,
});

obj.x = 10;
const a = obj.x;
const b = obj.doubled;

try { obj.x = -1; } catch (e) { accessLog.push(`throw:${e.message}`); }

console.log({ a, b, log: accessLog });
