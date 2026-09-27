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
var log = [];
function settle(ok, value) {
    return ok ? Promise.resolve(value) : Promise.reject(new Error(value));
}
function guarded(ok) {
    return __awaiter(this, void 0, void 0, function () {
        var value, error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    log.push("enter " + ok);
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, 4, 5]);
                    return [4 /*yield*/, settle(ok, "v" + ok)];
                case 2:
                    value = _a.sent();
                    log.push("got " + value);
                    return [2 /*return*/, value];
                case 3:
                    error_1 = _a.sent();
                    log.push("caught " + error_1.message);
                    return [2 /*return*/, "fallback"];
                case 4:
                    log.push("finally " + ok);
                    return [7 /*endfinally*/];
                case 5: return [2 /*return*/];
            }
        });
    });
}
function cleanup() {
    return __awaiter(this, void 0, void 0, function () {
        var count, _a, _b, error_2, _c;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    count = 0;
                    _d.label = 1;
                case 1:
                    _d.trys.push([1, 8, , 10]);
                    _a = count;
                    return [4 /*yield*/, Promise.resolve(1)];
                case 2:
                    count = _a + _d.sent();
                    _d.label = 3;
                case 3:
                    _d.trys.push([3, , 6, 7]);
                    _b = count;
                    return [4 /*yield*/, Promise.resolve(10)];
                case 4:
                    count = _b + _d.sent();
                    return [4 /*yield*/, settle(false, "inner")];
                case 5:
                    _d.sent();
                    return [3 /*break*/, 7];
                case 6:
                    count += 100;
                    log.push("inner finally " + count);
                    return [7 /*endfinally*/];
                case 7: return [3 /*break*/, 10];
                case 8:
                    error_2 = _d.sent();
                    log.push("outer caught " + error_2.message);
                    _c = count;
                    return [4 /*yield*/, Promise.resolve(1000)];
                case 9:
                    count = _c + _d.sent();
                    return [3 /*break*/, 10];
                case 10: return [2 /*return*/, count];
            }
        });
    });
}
function finallyAwait() {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, , 2, 4]);
                    return [4 /*yield*/, settle(true, "body")];
                case 1: return [2 /*return*/, _a.sent()];
                case 2: return [4 /*yield*/, Promise.resolve(0)];
                case 3:
                    _a.sent();
                    log.push("awaited in finally");
                    return [7 /*endfinally*/];
                case 4: return [2 /*return*/];
            }
        });
    });
}
function rethrow() {
    return __awaiter(this, void 0, void 0, function () {
        var error_3;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, , 3]);
                    return [4 /*yield*/, settle(false, "boom")];
                case 1:
                    _a.sent();
                    return [3 /*break*/, 3];
                case 2:
                    error_3 = _a.sent();
                    log.push("rethrowing " + error_3.message);
                    throw new Error("again " + error_3.message);
                case 3: return [2 /*return*/];
            }
        });
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function () {
        var _a, _b, _c, _d, _e, _f, _g, _h, error_4;
        return __generator(this, function (_j) {
            switch (_j.label) {
                case 0:
                    _b = (_a = console).log;
                    return [4 /*yield*/, guarded(true)];
                case 1:
                    _b.apply(_a, [_j.sent()]);
                    _d = (_c = console).log;
                    return [4 /*yield*/, guarded(false)];
                case 2:
                    _d.apply(_c, [_j.sent()]);
                    _f = (_e = console).log;
                    return [4 /*yield*/, cleanup()];
                case 3:
                    _f.apply(_e, [_j.sent()]);
                    _h = (_g = console).log;
                    return [4 /*yield*/, finallyAwait()];
                case 4:
                    _h.apply(_g, [_j.sent()]);
                    _j.label = 5;
                case 5:
                    _j.trys.push([5, 7, , 8]);
                    return [4 /*yield*/, rethrow()];
                case 6:
                    _j.sent();
                    return [3 /*break*/, 8];
                case 7:
                    error_4 = _j.sent();
                    console.log("main caught " + error_4.message);
                    return [3 /*break*/, 8];
                case 8:
                    console.log(log.join(";"));
                    return [2 /*return*/];
            }
        });
    });
}
main();
