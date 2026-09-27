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
function delay(value) {
    return new Promise((resolve) => setTimeout(() => resolve(value), 0));
}
function add(a, b) {
    return __awaiter(this, void 0, void 0, function* () {
        const left = yield delay(a);
        const right = yield delay(b);
        return left + right;
    });
}
function chain(start) {
    return __awaiter(this, void 0, void 0, function* () {
        const first = yield add(start, 1);
        const second = yield add(first, first);
        const third = yield Promise.resolve(second * 3);
        return "chain " + start + " -> " + first + "," + second + "," + third;
    });
}
function noAwait(label) {
    return __awaiter(this, void 0, void 0, function* () {
        return "plain " + label;
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(yield add(2, 3));
        console.log(yield chain(4));
        console.log(yield noAwait("x"));
        const values = yield Promise.all([add(1, 1), add(2, 2), chain(0)]);
        console.log(values.join("|"));
    });
}
main();
