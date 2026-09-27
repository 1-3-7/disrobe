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
Object.defineProperty(exports, "__esModule", { value: true });
function countArgs(first, ...rest) {
    return __awaiter(this, void 0, void 0, function* () {
        const total = yield Promise.resolve(rest.reduce((acc, value) => acc + value, first));
        return "args=" + (rest.length + 1) + " total=" + total;
    });
}
function withDefault(value_1) {
    return __awaiter(this, arguments, void 0, function* (value, scale = 3) {
        const base = yield Promise.resolve(value);
        return base * scale;
    });
}
function destructured(_a) {
    return __awaiter(this, arguments, void 0, function* ({ a, b }) {
        return (yield Promise.resolve(a)) - b;
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(yield countArgs(1, 2, 3, 4));
        console.log(yield withDefault(4));
        console.log(yield withDefault(4, 10));
        console.log(yield destructured({ a: 10, b: 4 }));
    });
}
main();
