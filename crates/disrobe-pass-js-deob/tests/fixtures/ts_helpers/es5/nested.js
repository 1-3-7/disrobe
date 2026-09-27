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
function double(value) {
    return Promise.resolve(value * 2);
}
function join(left, right) {
    return Promise.resolve(left + ":" + right);
}
function nestedCalls(seed) {
    return __awaiter(this, void 0, void 0, function () {
        var _a, _b, _c;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    _a = join;
                    return [4 /*yield*/, double(seed)];
                case 1:
                    _b = [_d.sent()];
                    _c = double;
                    return [4 /*yield*/, double(seed)];
                case 2: return [4 /*yield*/, _c.apply(void 0, [_d.sent()])];
                case 3: return [4 /*yield*/, _a.apply(void 0, _b.concat([_d.sent()]))];
                case 4: return [2 /*return*/, _d.sent()];
            }
        });
    });
}
function inExpressions(seed) {
    return __awaiter(this, void 0, void 0, function () {
        var sum, _a, pick, _b, flags, _c;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0: return [4 /*yield*/, double(seed)];
                case 1:
                    _a = (_d.sent());
                    return [4 /*yield*/, double(seed + 1)];
                case 2:
                    sum = _a + (_d.sent()) * 2;
                    if (!(seed > 2)) return [3 /*break*/, 4];
                    return [4 /*yield*/, double(sum)];
                case 3:
                    _b = _d.sent();
                    return [3 /*break*/, 6];
                case 4: return [4 /*yield*/, double(-sum)];
                case 5:
                    _b = _d.sent();
                    _d.label = 6;
                case 6:
                    pick = _b;
                    return [4 /*yield*/, double(1)];
                case 7:
                    _c = [_d.sent()];
                    return [4 /*yield*/, double(2)];
                case 8:
                    flags = _c.concat([_d.sent()]);
                    return [2 /*return*/, pick + flags[0] + flags[1]];
            }
        });
    });
}
function inner(label) {
    return __awaiter(this, void 0, void 0, function () {
        var part;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, Promise.resolve(label)];
                case 1:
                    part = _a.sent();
                    return [2 /*return*/, "<" + part + ">"];
            }
        });
    });
}
function outer() {
    return __awaiter(this, void 0, void 0, function () {
        var parts, _a, _b, _c, _d, _e, wrapped, _f, _g;
        var _this = this;
        return __generator(this, function (_h) {
            switch (_h.label) {
                case 0:
                    parts = [];
                    _b = (_a = parts).push;
                    return [4 /*yield*/, inner("a")];
                case 1:
                    _b.apply(_a, [_h.sent()]);
                    _d = (_c = parts).push;
                    _e = inner;
                    return [4 /*yield*/, inner("b")];
                case 2: return [4 /*yield*/, _e.apply(void 0, [_h.sent()])];
                case 3:
                    _d.apply(_c, [_h.sent()]);
                    wrapped = function (value) { return __awaiter(_this, void 0, void 0, function () { var _a; return __generator(this, function (_b) {
                        switch (_b.label) {
                            case 0:
                                _a = "[";
                                return [4 /*yield*/, inner(value)];
                            case 1: return [2 /*return*/, _a + (_b.sent()) + "]"];
                        }
                    }); }); };
                    _g = (_f = parts).push;
                    return [4 /*yield*/, wrapped("c")];
                case 4:
                    _g.apply(_f, [_h.sent()]);
                    return [2 /*return*/, parts.join("")];
            }
        });
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        return __generator(this, function (_j) {
            switch (_j.label) {
                case 0:
                    _b = (_a = console).log;
                    return [4 /*yield*/, nestedCalls(3)];
                case 1:
                    _b.apply(_a, [_j.sent()]);
                    _d = (_c = console).log;
                    return [4 /*yield*/, inExpressions(1)];
                case 2:
                    _d.apply(_c, [_j.sent()]);
                    _f = (_e = console).log;
                    return [4 /*yield*/, inExpressions(5)];
                case 3:
                    _f.apply(_e, [_j.sent()]);
                    _h = (_g = console).log;
                    return [4 /*yield*/, outer()];
                case 4:
                    _h.apply(_g, [_j.sent()]);
                    return [2 /*return*/];
            }
        });
    });
}
main();
