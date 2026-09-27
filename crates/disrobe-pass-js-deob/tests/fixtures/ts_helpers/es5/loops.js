"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
function tick(value) {
    return new Promise(function (resolve) { return setTimeout(function () { return resolve(value); }, 0); });
}
function sumRange(limit) {
    return __awaiter(this, void 0, void 0, function () {
        var total, index, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    total = 0;
                    index = 0;
                    _b.label = 1;
                case 1:
                    if (!(index < limit)) return [3 /*break*/, 4];
                    _a = total;
                    return [4 /*yield*/, tick(index)];
                case 2:
                    total = _a + _b.sent();
                    _b.label = 3;
                case 3:
                    index++;
                    return [3 /*break*/, 1];
                case 4: return [2 /*return*/, total];
            }
        });
    });
}
function countDown(start) {
    return __awaiter(this, void 0, void 0, function () {
        var seen, current, _a, _b;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    seen = [];
                    current = start;
                    _c.label = 1;
                case 1:
                    if (!(current > 0)) return [3 /*break*/, 3];
                    _b = (_a = seen).push;
                    return [4 /*yield*/, tick(current)];
                case 2:
                    _b.apply(_a, [_c.sent()]);
                    current -= 2;
                    return [3 /*break*/, 1];
                case 3: return [2 /*return*/, seen.join(",")];
            }
        });
    });
}
function doWhile() {
    return __awaiter(this, void 0, void 0, function () {
        var rounds;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    rounds = 0;
                    _a.label = 1;
                case 1: return [4 /*yield*/, tick(rounds + 1)];
                case 2:
                    rounds = _a.sent();
                    _a.label = 3;
                case 3:
                    if (rounds < 4) return [3 /*break*/, 1];
                    _a.label = 4;
                case 4: return [2 /*return*/, rounds];
            }
        });
    });
}
function overArray(items) {
    return __awaiter(this, void 0, void 0, function () {
        var out, _i, items_1, item, _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    out = "";
                    _i = 0, items_1 = items;
                    _b.label = 1;
                case 1:
                    if (!(_i < items_1.length)) return [3 /*break*/, 4];
                    item = items_1[_i];
                    _a = out;
                    return [4 /*yield*/, Promise.resolve(item)];
                case 2:
                    out = _a + (_b.sent()).toUpperCase();
                    _b.label = 3;
                case 3:
                    _i++;
                    return [3 /*break*/, 1];
                case 4: return [2 /*return*/, out];
            }
        });
    });
}
function skipAndStop(values) {
    return __awaiter(this, void 0, void 0, function () {
        var total, index, value;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    total = 0;
                    index = 0;
                    _a.label = 1;
                case 1:
                    if (!(index < values.length)) return [3 /*break*/, 4];
                    return [4 /*yield*/, tick(values[index])];
                case 2:
                    value = _a.sent();
                    if (value < 0) {
                        return [3 /*break*/, 3];
                    }
                    if (value > 100) {
                        return [3 /*break*/, 4];
                    }
                    total += value;
                    _a.label = 3;
                case 3:
                    index++;
                    return [3 /*break*/, 1];
                case 4: return [2 /*return*/, total];
            }
        });
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
        return __generator(this, function (_l) {
            switch (_l.label) {
                case 0:
                    _b = (_a = console).log;
                    return [4 /*yield*/, sumRange(5)];
                case 1:
                    _b.apply(_a, [_l.sent()]);
                    _d = (_c = console).log;
                    return [4 /*yield*/, countDown(7)];
                case 2:
                    _d.apply(_c, [_l.sent()]);
                    _f = (_e = console).log;
                    return [4 /*yield*/, doWhile()];
                case 3:
                    _f.apply(_e, [_l.sent()]);
                    _h = (_g = console).log;
                    return [4 /*yield*/, overArray(["a", "b", "c"])];
                case 4:
                    _h.apply(_g, [_l.sent()]);
                    _k = (_j = console).log;
                    return [4 /*yield*/, skipAndStop([1, -2, 3, 400, 5])];
                case 5:
                    _k.apply(_j, [_l.sent()]);
                    return [2 /*return*/];
            }
        });
    });
}
main();
