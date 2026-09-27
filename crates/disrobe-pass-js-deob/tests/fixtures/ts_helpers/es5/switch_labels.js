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
function answer(kind) {
    return Promise.resolve(kind.charCodeAt(0));
}
function route(kind) {
    return __awaiter(this, void 0, void 0, function () {
        var result, _a, _b, _c;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    result = "";
                    _a = kind;
                    switch (_a) {
                        case "a": return [3 /*break*/, 1];
                        case "b": return [3 /*break*/, 3];
                    }
                    return [3 /*break*/, 4];
                case 1:
                    _b = "alpha ";
                    return [4 /*yield*/, answer(kind)];
                case 2:
                    result = _b + (_d.sent());
                    return [3 /*break*/, 6];
                case 3:
                    result = "beta";
                    return [3 /*break*/, 6];
                case 4:
                    _c = "other ";
                    return [4 /*yield*/, answer(kind)];
                case 5:
                    result = _c + (_d.sent());
                    _d.label = 6;
                case 6: return [2 /*return*/, result];
            }
        });
    });
}
function labelled(grid) {
    return __awaiter(this, void 0, void 0, function () {
        var found, row, col, cell;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    found = [];
                    row = 0;
                    _a.label = 1;
                case 1:
                    if (!(row < grid.length)) return [3 /*break*/, 6];
                    col = 0;
                    _a.label = 2;
                case 2:
                    if (!(col < grid[row].length)) return [3 /*break*/, 5];
                    return [4 /*yield*/, Promise.resolve(grid[row][col])];
                case 3:
                    cell = _a.sent();
                    if (cell === 0) {
                        return [3 /*break*/, 5];
                    }
                    if (cell < 0) {
                        return [3 /*break*/, 6];
                    }
                    found.push(row + "." + col + "=" + cell);
                    _a.label = 4;
                case 4:
                    col++;
                    return [3 /*break*/, 2];
                case 5:
                    row++;
                    return [3 /*break*/, 1];
                case 6: return [2 /*return*/, found.join(" ")];
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
                    return [4 /*yield*/, route("a")];
                case 1:
                    _b.apply(_a, [_j.sent()]);
                    _d = (_c = console).log;
                    return [4 /*yield*/, route("b")];
                case 2:
                    _d.apply(_c, [_j.sent()]);
                    _f = (_e = console).log;
                    return [4 /*yield*/, route("z")];
                case 3:
                    _f.apply(_e, [_j.sent()]);
                    _h = (_g = console).log;
                    return [4 /*yield*/, labelled([[1, 2], [0, 3], [4, -1, 5], [6]])];
                case 4:
                    _h.apply(_g, [_j.sent()]);
                    return [2 /*return*/];
            }
        });
    });
}
main();
