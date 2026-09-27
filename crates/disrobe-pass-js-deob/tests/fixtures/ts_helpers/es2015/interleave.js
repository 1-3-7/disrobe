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
const order = [];
function worker(name, rounds) {
    return __awaiter(this, void 0, void 0, function* () {
        order.push(name + " start");
        for (let round = 0; round < rounds; round++) {
            yield null;
            order.push(name + " round " + round);
        }
        const settled = yield Promise.resolve(name.length);
        order.push(name + " settled " + settled);
        return name + " done";
    });
}
function returnsPromise() {
    return __awaiter(this, void 0, void 0, function* () {
        order.push("returnsPromise start");
        return Promise.resolve("inner promise");
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        const first = worker("alpha", 2);
        const second = worker("be", 3);
        const third = returnsPromise();
        order.push("sync end");
        const results = yield Promise.all([first, second, third]);
        console.log(results.join(","));
        console.log(order.join("\n"));
    });
}
main();
