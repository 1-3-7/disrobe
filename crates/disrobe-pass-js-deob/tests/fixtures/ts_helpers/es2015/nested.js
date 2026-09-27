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
function double(value) {
    return Promise.resolve(value * 2);
}
function join(left, right) {
    return Promise.resolve(left + ":" + right);
}
function nestedCalls(seed) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield join(yield double(seed), yield double(yield double(seed)));
    });
}
function inExpressions(seed) {
    return __awaiter(this, void 0, void 0, function* () {
        const sum = (yield double(seed)) + (yield double(seed + 1)) * 2;
        const pick = seed > 2 ? yield double(sum) : yield double(-sum);
        const flags = [yield double(1), yield double(2)];
        return pick + flags[0] + flags[1];
    });
}
function inner(label) {
    return __awaiter(this, void 0, void 0, function* () {
        const part = yield Promise.resolve(label);
        return "<" + part + ">";
    });
}
function outer() {
    return __awaiter(this, void 0, void 0, function* () {
        const parts = [];
        parts.push(yield inner("a"));
        parts.push(yield inner(yield inner("b")));
        const wrapped = (value) => __awaiter(this, void 0, void 0, function* () { return "[" + (yield inner(value)) + "]"; });
        parts.push(yield wrapped("c"));
        return parts.join("");
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(yield nestedCalls(3));
        console.log(yield inExpressions(1));
        console.log(yield inExpressions(5));
        console.log(yield outer());
    });
}
main();
